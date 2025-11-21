import pytest
from contextlib import AsyncExitStack
from tests import config
from tests.helpers import SetupParameters, setup_environment, setup_connections
from tests.helpers_vpn import connect_vpn, VpnConfig
from tests.utils import stun
from tests.utils.bindings import TelioAdapterType
from tests.utils.connection import ConnectionTag
from tests.utils.connection_util import (
    new_connection_by_tag,
    generate_connection_tracker_config,
)
from tests.utils.ping import ping


@pytest.mark.parametrize(
    "alpha_setup_params, public_ip",
    [
        pytest.param(
            SetupParameters(
                connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1,
                adapter_type_override=TelioAdapterType.NEP_TUN,
                is_meshnet=False,
            ),
            "10.0.254.1",
        ),
    ],
)
@pytest.mark.parametrize(
    "vpn_conf",
    [
        pytest.param(
            VpnConfig(config.WG_SERVER, ConnectionTag.DOCKER_VPN_1, True),
            id="wg_server",
        )
    ],
)
async def test_vpn_performance(
    alpha_setup_params: SetupParameters,
    vpn_conf: VpnConfig,
    public_ip: str,
) -> None:
    async with AsyncExitStack() as exit_stack:
        alpha_setup_params.connection_tracker_config = (
            generate_connection_tracker_config(
                alpha_setup_params.connection_tag,
                stun_limits=(1, 1),
                nlx_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.VM_LINUX_NLX_1
                    else (0, 0)
                ),
                vpn_1_limits=(
                    (1, 1)
                    if vpn_conf.conn_tag == ConnectionTag.DOCKER_VPN_1
                    else (0, 0)
                ),
            )
        )
        env = await exit_stack.enter_async_context(
            setup_environment(exit_stack, [alpha_setup_params], prepare_vpn=True)
        )

        alpha, *_ = env.nodes
        client_conn, *_ = [conn.connection for conn in env.connections]
        client_alpha, *_ = env.clients

        ip = await stun.get(client_conn, config.STUN_SERVER)
        assert ip == public_ip, f"wrong public IP before connecting to VPN {ip}"

        if vpn_conf.should_ping_client:
            vpn_connection, *_ = await setup_connections(
                exit_stack, [vpn_conf.conn_tag]
            )
            await connect_vpn(
                client_conn,
                vpn_connection.connection,
                client_alpha,
                alpha.ip_addresses[0],
                vpn_conf.server_conf,
            )
        else:
            await connect_vpn(
                client_conn,
                None,
                client_alpha,
                alpha.ip_addresses[0],
                vpn_conf.server_conf,
            )
