# relationships:
#   references: tests/acceptance/run.sh
.PHONY: acceptance
# The operator prepares the bootstrap image outside this target; see the guide.
acceptance:
	./tests/acceptance/run.sh
