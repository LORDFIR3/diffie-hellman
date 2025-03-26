FROM python:latest

WORKDIR /app

RUN python -m ensurepip --upgrade

COPY requirements.txt .

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]