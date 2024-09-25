# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install necessary libraries for cryptography
RUN apt-get update && apt-get install -y \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Expose port 5000 for the Flask app
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Run the command to start the Flask app
CMD ["flask", "run", "--host=0.0.0.0"]
