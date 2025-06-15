# QuestionnaireApp - Professional Survey Platform

This is a professional, full-featured web application built with Flask that allows administrators to create and manage items (like products or topics) and associate a series of questions with them. Regular users can then view these items and answer the questionnaires.

The application features a clean, modern, and responsive user interface designed for a professional user experience.

## Key Features

- **Separate User & Admin Roles:** Different dashboards and permissions for regular users and administrators.
- **Admin Dashboard:** Admins can add, edit, and delete items and their associated questions. They can also view all user submissions.
- **Engaging Questionnaires:** Users can view items, watch an attached video, and then take a multi-question survey with a progress bar.
- **Secure Authentication:** User registration and login functionality with password hashing using Flask-Bcrypt.
- **Database-Driven:** Uses SQLAlchemy to manage all data, including users, items, questions, and results.
- **Professional Design:** A clean and modern UI built with Bootstrap and custom CSS.

## Setup and Run the Application Locally

Follow these steps to run the project on your local machine.

### 1. Prerequisites

- Python 3.x
- `pip` (Python package installer)

### 2. Clone the Repository

(You can also download the ZIP file and extract it)
```bash
git clone https://github.com/Tayyriaz/QuestionnaireApp-Professional-Survey-Platform.git
cd QuestionnaireApp-Professional-Survey-Platform
```

### 3. Install Dependencies

Create a virtual environment (recommended) and install the required packages using the `requirements.txt` file.

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate

# Install the packages
pip install -r requirements.txt
```

### 4. Initialize the Database

The first time you run the app, it will automatically create the `project.db` database file and the necessary tables.

### 5. Run the Application

```bash
flask run
```
The application will be running at `http://127.0.0.1:5000`.

## Default Admin Credentials

You can use the following credentials to log in as an administrator:

- **Email:** `admin@example.com`
- **Password:** `admin` 


these are requirment
Flask==2.2.2
Flask-SQLAlchemy==2.5.1
Flask-Bcrypt==1.0.1 
