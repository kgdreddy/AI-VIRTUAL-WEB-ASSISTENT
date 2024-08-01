from http import server
import subprocess
import wolframalpha
import pyttsx3
import pywhatkit
import datetime
import speech_recognition as sr
import pyaudio
import wikipedia
import webbrowser
import os
import time
import json
import random
import shutil
import requests
from urllib.request import urlopen
import pyjokes
from bs4 import BeautifulSoup
import win32com.client as wincl
engine = pyttsx3.init('sapi5')
voices = engine.getProperty('voices')
engine.setProperty('voice', voices[1].id)


def speak(audio):
    engine.say(audio)
    engine.runAndWait()


def wishMe():
    hour = int(datetime.datetime.now().hour)
    if hour >= 0 and hour < 12:
        speak("Good Morning friend !!")
    elif hour >= 12 and hour < 18:
        speak("Good Afternoon friend!!")
    else:
        speak("Good Evening friend!!")
    assname = ("Siri")
    speak("I am your Assistant")
    speak(assname)
    speak("How can I help you !!")


def takeCommand():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        r.pause_threshold = 0.5
        audio = r.listen(source)

    try:
        print("Recognizing..")
        query = r.recognize_google(audio, language='en-in')
        print(f"User said:{query}\n")
        speak(query)
    except Exception as e:
        print("Unable to Recognize your voice.")
        return "None"
    return query


if __name__ == "__main__":
    wishMe()
    while True:
        query = takeCommand().lower()
        if 'open youtube' in query:
            speak("Here you go!!")
            webbrowser.open("www.youtube.com")

        elif 'play' in query and 'youtube' in query:
            song = query.replace('play', '').replace('youtube', '').strip()
            speak(f"Playing {song} on YouTube")
            pywhatkit.playonyt(song)
        elif 'open google' in query:
            speak("here you go!!")
            webbrowser.open("www.google.com")
        elif 'search' in query:
            speak("What do you want me to search for?")
            search_query = takeCommand().lower()
            if search_query:
                url = f"https://www.google.com/search?q={search_query}"
                webbrowser.get().open(url)
                speak(f"Here are the search results for {search_query}")
            else:
                speak("Sorry, I didn't catch that. Could you please repeat?")

        elif 'the time' in query:
            strTime = datetime.datetime.now().strftime("%H:%M:%S")
            speak(f"the time is {strTime}")
            print(strTime)
        elif 'joke' in query:
            s = pyjokes.get_joke()
            speak(s)
            print(s)

        elif 'shutdown system' in query:
            speak("Hold On a Sec ! Your system is on its way to shut down")
            subprocess.call('shutdown / p /f')
        elif 'search' in query or 'play' in query:
            query = query.replace("search", " ")
            query = query.replace("play", " ")
            webbrowser.open(query)
        elif 'where is' in query:
            query = query.replace("where is", " ")
            location = query
            speak("user asked to locate")
            speak(location)
            webbrowser.open(
                "https://www.google.com/maps/@17.3917689,78.4638162,15z/place/" + location + " ")
        elif "temperature" in query:
            search = "temperature"
            url = f"https://www.google.com/search?q={search}"
            r = requests.get(url)
            data = BeautifulSoup(r.text, "html.parser")
            temp = data.find("div", class_="BNeawe").text
            speak(f"current{search}is {temp}")
            print(temp)

        elif 'goodbye' in query or 'bye' in query or 'stop' in query:
            speak("Thanks for your time and Goodbye!")
            exit()