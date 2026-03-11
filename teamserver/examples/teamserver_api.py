import havoc


def on_agent_event(event):
    agent = event.agent
    if agent is None:
        return

    info = agent.info
    print(f"[plugin] {event.event_type}: {info['Hostname']}\\{info['Username']}")


def echo_command(agent, args):
    payload = " ".join(args).encode()
    agent.task(0x63, payload)


havoc.RegisterCallback("agent_checkin", on_agent_event)
havoc.RegisterCallback("command_output", on_agent_event)
havoc.RegisterCommand("echo-demo", "Queue a demo task payload for the selected agent", echo_command)
