FROM python:3.11-slim

WORKDIR /app

# Копируем requirements.txt ПЕРВЫМ (для кэширования)
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем остальные файлы
COPY . .

# Создаем папку templates если её нет
RUN mkdir -p templates

# Запускаем приложение
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
