# Build stage
FROM docker.io/python:3.10.11-bullseye AS builder

WORKDIR /app

COPY app.sh .

CMD ["./app.sh"]
