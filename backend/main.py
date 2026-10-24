from fastapi import FastAPI
from pydantic import BaseModel, HttpUrl

from website_analyzer import analyze_website
from cookie_analyzer import analyze_cookies


app = FastAPI(
    title="Website Security API",
    description="Website security and cookie configuration analyzer",
    version="1.0.0"
)


class WebsiteRequest(BaseModel):
    url: HttpUrl


@app.get("/")
def home():
    return {
        "message": "Website Security API is running!"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze")
def analyze_website_endpoint(website: WebsiteRequest):

    url = str(website.url)

    # Analyze the website
    website_data = analyze_website(url)

    # If the website could not be reached,
    # return the website analysis directly.
    if not website_data.get("reachable", False):
        return website_data

    # Analyze cookies received from the website
    response = website_data.pop("response")

    cookie_data = analyze_cookies(response)

    # Close the HTTP response
    response.close()

    # Combine website and cookie analysis
    return {
        **website_data,
        "cookies": cookie_data
    }