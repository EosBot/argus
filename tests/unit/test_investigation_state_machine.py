from backend.orchestrator.state_machine import InvestigationStateMachine, InvestigationStatus


def test_state_machine_initializes_without_overwriting_public_property() -> None:
    machine = InvestigationStateMachine("case-1")

    assert machine.state is InvestigationStatus.PENDING
    assert machine.to_dict()["state"] == "pending"


def test_state_machine_executes_investigation_lifecycle() -> None:
    machine = InvestigationStateMachine("case-1")

    machine.start_planning()
    machine.start_running()
    machine.start_correlating()
    machine.start_reporting()
    machine.complete()

    assert machine.state is InvestigationStatus.COMPLETE
    assert machine.is_terminal is True
    assert [entry["to_state"] for entry in machine.get_state_history()] == [
        "planning",
        "running",
        "correlating",
        "reporting",
        "complete",
    ]
