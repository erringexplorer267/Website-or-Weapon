# 1. Use an official Python base image
FROM python:3.11-slim

# 2. Set the working directory inside the container
WORKDIR /app

# 3. Copy the dependencies file first to leverage Docker caching
COPY requirements.txt requirements.txt

# 4. Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copy the rest of the application code and the saved model
# This includes app.py and model.pkl
COPY . .

# 6. Expose the port where your application will listen
EXPOSE 8080

# 7. Define the command to run the application using Gunicorn (a production web server)
# 'app:app' assumes your Flask/FastAPI app object is named 'app' in 'app.py'
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]