// 用户表：空表、重复 uid、重复密钥必须拒绝；合法表可按 uid 查找。
//
// 本文件由 `tests/eih.rs` 用 `include!` 文本并入同一模块；
// 共享助手在 `tests/eih.rs` 入口文件，`use` 全部写在入口文件。
#[test]
fn user_table_rejects_empty_duplicates_and_is_lookupable() {
    assert!(matches!(
        UserTable::new(Vec::new()),
        Err(Error::EihUserTable)
    ));
    let user = key(Method::Aes128, 0x22);
    assert!(matches!(
        UserTable::new(vec![
            User {
                uid: 1,
                key: user.clone()
            },
            User {
                uid: 1,
                key: key(Method::Aes128, 0x33)
            }
        ]),
        Err(Error::EihUserTable)
    ));
    assert!(matches!(
        UserTable::new(vec![
            User {
                uid: 1,
                key: user.clone()
            },
            User {
                uid: 2,
                key: user.clone()
            }
        ]),
        Err(Error::EihUserTable)
    ));
    let table = UserTable::new(vec![User { uid: 9, key: user }]).expect("合法表");
    assert_eq!(table.len(), 1);
    assert!(!table.is_empty());
    assert_eq!(table.by_uid(9).map(|user| user.uid), Some(9));
    assert!(table.by_uid(10).is_none());
    assert_eq!(table.method(), Method::Aes128);
}
