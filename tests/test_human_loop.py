from threading import Thread
from time import monotonic, sleep

from lattice_mind.core.human_loop import HumanLoopManager


def test_questions_are_associated_with_active_run_and_answered():
    manager = HumanLoopManager(default_timeout=2)
    manager.begin_run("run-owned")
    result = []
    worker = Thread(target=lambda: result.append(manager.ask_user("Proceed?")))
    worker.start()

    deadline = monotonic() + 1
    questions = []
    while monotonic() < deadline:
        questions = manager.get_pending()
        if questions:
            break
        sleep(0.01)

    assert questions[0]["run_id"] == "run-owned"
    assert manager.answer(questions[0]["id"], "yes")
    worker.join(timeout=2)
    assert result == ["yes"]
