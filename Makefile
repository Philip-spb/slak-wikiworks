# target: make tunnel
tunnel:
	ssh -R 80:localhost:8000 localhost.run

# target: pep8 - Run code style test
pep8:
	flake8 --statistics --count
