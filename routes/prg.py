from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from analysis.callgraph import build_backend_callgraph
from crypto.owf import evaluate, verify_hardness
from crypto.prg import hill_prg
from crypto.prg import verify_prg_as_owf_hardness
from crypto.stat_tests import run_basic_nist_suite


router = APIRouter()


class PRGRequest(BaseModel):
	seed: str = Field(..., examples=["a3f2"])
	length: int = Field(..., ge=0, examples=[16])
	foundation: str = Field(..., examples=["AES"])


class PRGWithSeedLengthRequest(BaseModel):
	seed: str = Field(..., examples=["a3f2"])
	extension_length: int = Field(..., ge=0, examples=[16])
	foundation: str = Field(..., examples=["AES"])


class RandomnessTestRequest(BaseModel):
	bits: str | None = Field(default=None, examples=["0101010101"])
	seed: str | None = Field(default=None, examples=["a3f2"])
	length: int = Field(default=128, ge=1, examples=[128])
	foundation: str = Field(default="AES", examples=["AES"])
	alpha: float = Field(default=0.01, gt=0.0, lt=1.0)


class OWFEvaluateRequest(BaseModel):
	x: str = Field(..., examples=["a3f2"])
	foundation: str = Field(..., examples=["AES"])


class OWFHardnessRequest(BaseModel):
	x: str = Field(..., examples=["a3f2"])
	foundation: str = Field(..., examples=["AES"])
	attempts: int = Field(default=64, ge=1, le=10000)


class PRGAsOWFRequest(BaseModel):
	seed: str = Field(..., examples=["a3f2"])
	foundation: str = Field(..., examples=["AES"])
	output_length: int = Field(default=128, ge=1, le=100000)
	attempts: int = Field(default=64, ge=1, le=10000)


@router.post("/prg")
def run_prg(payload: PRGRequest):
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")

	try:
		result = hill_prg(seed=payload.seed, length=payload.length, foundation=foundation)
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc

	return result


@router.post("/prg/extend")
def run_prg_extend(payload: PRGWithSeedLengthRequest):
	"""PA-style mode: output length = n + l where n is seed bit-length."""
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")

	clean_seed = payload.seed.lower().replace("0x", "")
	n = max(1, len(clean_seed) * 4)
	total_length = n + payload.extension_length

	try:
		result = hill_prg(seed=payload.seed, length=total_length, foundation=foundation)
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc

	return {
		"seed_bits": n,
		"extension_length": payload.extension_length,
		"total_length": total_length,
		**result,
	}


@router.post("/prg/tests")
def run_randomness_tests(payload: RandomnessTestRequest):
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")

	try:
		if payload.bits is not None:
			bits = payload.bits
		else:
			if payload.seed is None:
				raise HTTPException(
					status_code=400,
					detail="Provide either bits, or seed + length + foundation",
				)
			bits = hill_prg(
				seed=payload.seed,
				length=payload.length,
				foundation=foundation,
			)["output"]

		return {
			"bits": bits,
			"summary": run_basic_nist_suite(bits, alpha=payload.alpha),
		}
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/owf/evaluate")
def evaluate_owf(payload: OWFEvaluateRequest):
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")
	try:
		return {
			"input": payload.x,
			"foundation": foundation,
			"output": evaluate(payload.x, foundation),
		}
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/owf/verify-hardness")
def verify_owf_hardness(payload: OWFHardnessRequest):
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")
	try:
		return verify_hardness(payload.x, foundation, attempts=payload.attempts)
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/prg/as-owf")
def verify_prg_to_owf(payload: PRGAsOWFRequest):
	foundation = payload.foundation.upper()
	if foundation not in {"AES", "DLP"}:
		raise HTTPException(status_code=400, detail="foundation must be AES or DLP")
	try:
		return verify_prg_as_owf_hardness(
			seed=payload.seed,
			foundation=foundation,
			output_length=payload.output_length,
			attempts=payload.attempts,
		)
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/backend/callgraph")
def backend_callgraph():
	return build_backend_callgraph()
