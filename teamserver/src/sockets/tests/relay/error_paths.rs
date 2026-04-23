use super::super::super::SocketRelayError;
use super::super::{sample_agent, test_manager};

#[tokio::test]
async fn write_client_data_returns_client_not_found_for_unknown_agent()
-> Result<(), SocketRelayError> {
    let (_database, _registry, manager) = test_manager().await?;

    let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));

    Ok(())
}

#[tokio::test]
async fn write_client_data_returns_client_not_found_for_unknown_socket()
-> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    manager.add_socks_server(0xDEAD_BEEF, "0").await?;

    let result = manager.write_client_data(0xDEAD_BEEF, 0x1234_5678, b"relay").await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));
    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}

#[tokio::test]
async fn close_client_returns_client_not_found_for_unknown_agent() -> Result<(), SocketRelayError> {
    let (_database, _registry, manager) = test_manager().await?;

    let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));

    Ok(())
}

#[tokio::test]
async fn close_client_returns_client_not_found_for_unknown_socket() -> Result<(), SocketRelayError>
{
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    manager.add_socks_server(0xDEAD_BEEF, "0").await?;

    let result = manager.close_client(0xDEAD_BEEF, 0x1234_5678).await;

    assert!(matches!(
        result,
        Err(SocketRelayError::ClientNotFound { agent_id, socket_id })
            if agent_id == 0xDEAD_BEEF && socket_id == 0x1234_5678
    ));
    manager.clear_socks_servers(0xDEAD_BEEF).await?;

    Ok(())
}
