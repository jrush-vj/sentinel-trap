"""A benign corpus used to reject over-broad learned rules and to test built-ins for false positives.

No built-in rule may match any of these EXCEPT the deliberately eager BI-PI-EXFIL-EAGER rule,
which flags FALSE_POSITIVE_EXAMPLE (that drives the Mark-as-safe self-correction demo).
"""
from __future__ import annotations

# ~70 benign inputs: customer names, support questions, and SQL-looking-but-harmless phrases.
CLEAN_CORPUS: list[str] = [
    # customer names / lookups (incl. tricky apostrophes and 'or'/'union' substrings)
    "alice", "bob", "garcia", "O'Brien", "D'Angelo", "Mary-Jane", "José", "Søren",
    "Tom Sawyer", "Union City", "union station hours", "Orlando", "Doris", "Corazon",
    "Normandy", "Georgia", "selection", "José O'Neill", "McDonald", "Anne-Marie",
    "Zhang Wei", "Umar Farah", "customer 1234", "order #5567", "plan upgrade request",
    # normal support questions
    "what are your support hours?", "how do i upgrade my plan?", "do you offer refunds?",
    "can you help me change my email address?", "my invoice looks wrong, who do i contact?",
    "is there a student discount?", "how do i cancel my subscription?",
    "what payment methods do you accept?", "where can i download my receipt?",
    "how long does onboarding take?", "can i add a teammate to my account?",
    "what is included in the pro plan?", "do you have an api?", "how do i reset my settings?",
    "the dashboard is loading slowly today", "i was charged twice this month",
    "please update my billing address", "what timezone is support in?",
    "how do i export my data?", "can i get a demo of enterprise?",
    "thanks for the quick help earlier!", "is my data encrypted at rest?",
    # SQL/keyword-looking but harmless
    "select a plan that fits your team", "i want to select the pro plan",
    "we need to union our two accounts into one", "please update me on the ticket",
    "drop me an email when it's ready", "insert my new card details in settings",
    "order history from last year", "create a new workspace for marketing",
    "delete my old payment method please", "the order was delivered or so i thought",
    "a and b both need access", "1 or 2 seats is fine", "between 1 and 5 users",
    "show me my recent orders", "list my active subscriptions",
    "where do i see my account information", "tell me about your pricing",
    "give me a quick overview of features", "send me the onboarding guide",
    "what is your refund policy", "how secure is my password stored",
    # longer natural sentences
    "I'm evaluating NovaMind for my startup and want to understand the Team plan limits.",
    "Could someone from support call me tomorrow between 9 and 11 am about my invoice?",
    "We migrated from a competitor and need help importing our customer list.",
    "My colleague and I are both admins; can we each have separate logins?",
    "The union of our two trial accounts should keep the earlier start date.",
    "Please select the option that best matches an enterprise rollout for 200 users.",
]

# Deliberate false-positive: a perfectly benign question that the eager rule flags as suspicious,
# so the demo can show MARK AS SAFE correcting the system. After mark-safe this input passes.
FALSE_POSITIVE_EXAMPLE = "Can you show me how to reset my password?"

# A few benign 3-word probes used by the validator to reject overly broad learned rules.
BENIGN_WORD_PROBES = ["account billing settings", "upgrade plan today", "reset email address",
                      "export my data", "team member access"]
