from typing import Union
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI

from attacks.deauth import run_deauth_attack
from models import deauthRequest

app = FastAPI(
    title="Airstrike API",
    description="An API to serve and simulate ethical cyber attack representations",
    version="1.0.0",
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],  
    allow_headers=["*"], 
)

@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/attacks")
def attacks(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}


@app.get("/attacks/deauth")
def deauth(data: deauthRequest):
    
    result = run_deauth_attack(data.bssid, data.interface)
    return {"data": result}