PYTHON ?= python3
EXAMPLE_ENV ?= PYTHONPATH=src

.PHONY: test example-buzz example-mcp example-mcp-host example-mcp-enforcing-mock example-multistep examples install

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

install:
	$(PYTHON) -m pip install .

example-buzz:
	$(EXAMPLE_ENV) $(PYTHON) examples/integrations/buzz_approval_flow.py

example-mcp:
	$(EXAMPLE_ENV) $(PYTHON) examples/integrations/existing_mcp_adapter.py

example-mcp-host:
	$(EXAMPLE_ENV) $(PYTHON) examples/integrations/mcp_host_smoke.py

example-mcp-enforcing-mock:
	$(EXAMPLE_ENV) $(PYTHON) examples/integrations/existing_mcp_adapter.py --enforcing-demo

example-multistep:
	$(EXAMPLE_ENV) $(PYTHON) examples/integrations/multi_step_flow.py

examples: example-buzz example-mcp example-mcp-host example-multistep
