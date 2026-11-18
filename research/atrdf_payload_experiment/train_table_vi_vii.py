"""Do not train Table VI/VII with jndi_lookup.

That 14-feature protocol scored 1.000 on both tables. Use
train_six_family_heldout.py (10 request statistics, no flags).
"""

raise SystemExit(
    "jndi_lookup in the forest made Table VI and Table VII 1.000. "
    "Run research/atrdf_payload_experiment/train_six_family_heldout.py"
)
