FROM python:3.9-alpine

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["flask", "--app", "Website", "run", "-p", "3000", "--host=0.0.0.0"]
#Image name is eddiephelan/awscloudproject:latest