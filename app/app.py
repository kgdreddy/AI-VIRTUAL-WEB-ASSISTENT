import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import matplotlib.dates as mdates
from matplotlib.figure import Figure
import time

# Setup the database
engine = create_engine('sqlite:///credential.db')
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

# Define the User model
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password = Column(String, nullable=False)

Base.metadata.create_all(engine)

# Helper functions for authentication
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, plain_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password)

def add_user(username, password):
    hashed_pw = hash_password(password)
    new_user = User(username=username, password=hashed_pw)
    session.add(new_user)
    session.commit()

def validate_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and check_password(user.password, password):
        return True
    return False

# Time series functions
def generate_time_series_data():
    dates = pd.date_range(start='1/1/2020', periods=100)
    data = np.random.randn(100).cumsum()
    return pd.DataFrame(data, index=dates, columns=['Value'])

def execute(plot_placeholder):
    st.subheader("Live Time Series Data")

    x_data, y_data = [], []
    fig, ax = plt.subplots()
    line, = ax.plot_date(x_data, y_data, '-')

    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    fig.autofmt_xdate()

    def update_plot():
        current_time = datetime.now()
        x_data.append(current_time)
        y_data.append(np.random.randint(0, 100))

        start_time = current_time - timedelta(minutes=1)

        while x_data and x_data[0] < start_time:
            x_data.pop(0)
            y_data.pop(0)

        line.set_data(x_data, y_data)
        ax.set_xlim(start_time, current_time)
        ax.relim()
        ax.autoscale_view()

        plot_placeholder.pyplot(fig)
    
    while True:
        update_plot()
        time.sleep(1)

# Initialize session state variables
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = ''

# Streamlit app
st.title("Authentication System")

# Navigation
if st.session_state['logged_in']:
    menu = ["Home", "Dashboard", "Time Series"]
else:
    menu = ["Home", "Login", "SignUp"]

choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Home")
    if st.session_state['logged_in']:
        plot_placeholder = st.empty()
        execute(plot_placeholder)
    else:
        st.info("Please log in to see the time series data.")

elif choice == "Login":
    if st.session_state['logged_in']:
        st.warning("You are already logged in!")
    else:
        st.subheader("Login Section")

        username = st.text_input("Username")
        password = st.text_input("Password", type='password')

        if st.button("Login"):
            if validate_user(username, password):
                st.success(f"Welcome {username}!")
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.experimental_rerun()
            else:
                st.warning("Incorrect Username/Password")

elif choice == "SignUp":
    if st.session_state['logged_in']:
        st.warning("You are already logged in!")
    else:
        st.subheader("Create New Account")

        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type='password')
        confirm_password = st.text_input("Confirm Password", type='password')

        if st.button("SignUp"):
            if new_password == confirm_password:
                add_user(new_username, new_password)
                st.success("Account created successfully!")
                st.info("Go to Login Menu to login")
            else:
                st.warning("Passwords do not match")

elif choice == "Dashboard":
    if st.session_state['logged_in']:
        st.subheader(f"Welcome to your dashboard, {st.session_state['username']}!")
        if st.button("Logout"):
            st.session_state['logged_in'] = False
            st.session_state['username'] = ''
            st.info("Logged out successfully")
            st.experimental_rerun()
    else:
        st.warning("You need to login first!")

elif choice == "Time Series":
    if st.session_state['logged_in']:
        plot_placeholder = st.empty()
        execute(plot_placeholder)
    else:
        st.warning("You need to login first!")
