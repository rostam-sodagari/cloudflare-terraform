# Domain test fixtures

These fake zones support validator, resync, and Terraform regression tests.
They are outside `domains/` and are never selected for live deployment.

`python cf.py test-all` copies them into a temporary repository layout before running mock plans.
The end-to-end test does the same for its local fake API. Do not run Terraform directly from these fixture folders: their module paths expect the temporary `domains/<name>/` layout.
