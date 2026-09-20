.PHONY: help install streamlit streamlit-build streamlit-up streamlit-down streamlit-logs test test-streamlit test-laravel
help:
	@printf '%s\n' 'make install          Install Python dependencies' 'make streamlit        Run Streamlit locally without Docker' 'make streamlit-build  Build the Streamlit Docker image' 'make streamlit-up     Run Streamlit at http://localhost:8501' 'make streamlit-down   Stop the local Streamlit container' 'make streamlit-logs   Follow container logs' 'make test             Run Streamlit and Laravel tests'
install:
	python -m pip install -r requirements.txt
streamlit:
	streamlit run streamlit_app.py --server.address=0.0.0.0 --server.port=8501
streamlit-build:
	docker build -f Dockerfile.streamlit -t cleaning-laravelmail-streamlit:local .
streamlit-up:
	docker compose -f docker-compose.streamlit.yml up --build -d
streamlit-down:
	docker compose -f docker-compose.streamlit.yml down
streamlit-logs:
	docker compose -f docker-compose.streamlit.yml logs -f streamlit
test: test-streamlit test-laravel
test-streamlit:
	python -m py_compile streamlit_app.py
test-laravel:
	php artisan test
