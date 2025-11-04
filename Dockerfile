FROM python:3.11
WORKDIR /app
COPY requirements.txt .
COPY . /app
# RUN apt-get update


# Create caluser user and set up home directory
RUN useradd -m -d /home/cybercrew cybercrew
RUN chown -R cybercrew:cybercrew /app /home/cybercrew

#RUN mkdir -p /app/instance && chown -R cybercrew:cybercrew /app/instance


RUN touch /var/log/gunicorn-error.log 

USER cybercrew

ENV PATH="/home/cybercrew/.local/bin:/usr/local/bin:/usr/bin:/bin"

RUN pip install --no-cache-dir -r requirements.txt


ENV ENV=prod


CMD ["python", "/app/main.py"]

