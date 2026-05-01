from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routes.prg import router as prg_router
from routes.pa2 import router as pa2_router
from routes.pa3 import router as pa3_router
from routes.pa3_cpa_game import router as pa3_cpa_game_router
from routes.pa4 import router as pa4_router
from routes.pa5 import router as pa5_router
from routes.pa6 import router as pa6_router
from routes.pa7 import router as pa7_router
from routes.pa8 import router as pa8_router
from routes.pa9 import router as pa9_router
from routes.pa10 import router as pa10_router
from routes.pa11 import router as pa11_router
from routes.pa12 import router as pa12_router
from routes.pa13 import router as pa13_router
from routes.pa14 import router as pa14_router
from routes.pa15 import router as pa15_router
from routes.pa16 import router as pa16_router
from routes.pa17 import router as pa17_router
from routes.pa18 import router as pa18_router
from routes.pa19 import router as pa19_router
from routes.pa20 import router as pa20_router


app = FastAPI(title="Minicrypt PA1 Backend")

origins = [
    "http://localhost:5173",   # local dev
    "https://encrypt-it-out.netlify.app",  # actual site LOL -> deployed on etlify
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
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
app.include_router(pa5_router)
app.include_router(pa6_router, prefix="/api", tags=["PA6"])
app.include_router(pa7_router, prefix="/api", tags=["PA7"])
app.include_router(pa8_router, prefix="/api", tags=["PA8"])
app.include_router(pa9_router, prefix="/api", tags=["PA9"])
app.include_router(pa10_router, prefix="/api", tags=["PA10"])
app.include_router(pa11_router, prefix="/api", tags=["PA11"])
app.include_router(pa12_router, prefix="/api", tags=["PA12"])
app.include_router(pa13_router, prefix="/api", tags=["PA13"])
app.include_router(pa14_router, prefix="/api", tags=["PA14"])
app.include_router(pa15_router, prefix="/api", tags=["PA15"])
app.include_router(pa16_router, prefix="/api", tags=["PA16"])
app.include_router(pa17_router, prefix="/api", tags=["PA17"])
app.include_router(pa18_router, prefix="/api", tags=["PA18"])
app.include_router(pa19_router, prefix="/api", tags=["PA19"])
app.include_router(pa20_router, prefix="/api", tags=["PA20"])
