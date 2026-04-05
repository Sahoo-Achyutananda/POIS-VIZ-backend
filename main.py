from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.prg import router as prg_router
from routes.pa2 import router as pa2_router
from routes.pa3 import router as pa3_router
from routes.pa3_cpa_game import router as pa3_cpa_game_router
from routes.pa4 import router as pa4_router


app = FastAPI(title="Minicrypt PA1 Backend")

# CORS is enabled so the React frontend can call this API from another origin.
app.add_middleware(
	CORSMiddleware,
	allow_origins=["*"],
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)


@app.get("/health")
def health_check():
	return {"status": "ok"}


app.include_router(prg_router, prefix="/api", tags=["PRG"])
app.include_router(pa2_router, prefix="/api", tags=["PA2"])
app.include_router(pa3_router, prefix="/api", tags=["PA3"])
app.include_router(pa3_cpa_game_router, prefix="/api", tags=["PA3_GAME"])
app.include_router(pa4_router, prefix="/api", tags=["PA4"])
