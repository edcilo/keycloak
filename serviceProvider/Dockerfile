FROM python:3.9

WORKDIR /app

COPY ./requirements.txt ./requirements.txt
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["fastapi", "dev", "--host=0.0.0.0", "--port=8080", "main.py"]
