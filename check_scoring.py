"""Quick scoring sanity-check after SSTI/IDOR seed tightening."""
import pathlib

from lattice_mind.core.confidence import ConfidencePool
from lattice_mind.core.executor import TreeExecutor
from lattice_mind.core.tree_loader import get_tree_registry
from lattice_mind.core.types import ChallengeDescriptor, ChallengeType

reg = get_tree_registry()
reg.load_from_directory(str(pathlib.Path("lattice_mind/trees/yaml")))

web_trees = [t for t in reg.list_trees() if t.category == "web" and t.enabled]

def score_context(label, tech_stack, found_paths, params):
    pool = ConfidencePool()
    executor = TreeExecutor(pool)
    context = {
        "challenge": ChallengeDescriptor(type=ChallengeType.WEB, url="http://test.com"),
        "tech_stack": tech_stack,
        "found_paths": found_paths,
        "params": params,
        "observations": {},
    }
    for tree in web_trees:
        executor.evaluate_seeds(tree, context)

    print(f"\n=== {label} ===")
    print(f"  tech_stack:  {tech_stack}")
    print(f"  params:      {params}")
    print(f"  found_paths: {found_paths}")
    print()
    scores = []
    for tree in web_trees:
        score = pool.get_tree_confidence(tree.id).score
        scores.append((tree.id, score))
    scores.sort(key=lambda x: x[1], reverse=True)
    for tid, score in scores:
        bar = "#" * int(score * 30)
        print(f"  {tid:<35} {score:.3f}  {bar}")


# Scenario 1: Generic web app — fallback params, just Python server header
score_context(
    "BEFORE FIX scenario: generic Python app (no template engine, fallback params)",
    tech_stack=["python"],
    found_paths=[],
    params=["id", "query", "name", "user"],
)

# Scenario 2: Real SSTI target — Flask+Jinja2 with /render and template param
score_context(
    "Real SSTI target: Flask + Jinja2, /render path, template param",
    tech_stack=["python", "flask", "jinja2"],
    found_paths=["/render", "/login"],
    params=["template", "name"],
)

# Scenario 3: Real IDOR target — explicit user_id / order_id params with /user endpoint
score_context(
    "Real IDOR target: user_id + order_id params, /user + /order endpoints",
    tech_stack=["php"],
    found_paths=["/user", "/order", "/admin"],
    params=["user_id", "order_id", "token"],
)

# Scenario 4: Real SQLi target — PHP app with id param, /login discovered
score_context(
    "Real SQLi target: PHP, id param, /login path",
    tech_stack=["php"],
    found_paths=["/login", "/admin"],
    params=["id", "user", "page"],
)
