FROM python:3.9

WORKDIR /app

COPY ./requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

EXPOSE 8000

CMD ["fastapi", "dev", "--host=0.0.0.0", "--port=8000", "main.py"]
