import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from routes import router

app = FastAPI(
    title="API Discovery Platform",
    description="Discovers, classifies, and security-evaluates APIs from a target domain and source repository.",
    version="2.0.0",
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
