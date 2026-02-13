from fastapi import APIRouter, Depends
from agent.auth import verify_signature
from agent.config import Config
from agent.unil.asyncall import asyncall
from agent.docker_client import DOCKER
from shared.schemas.manifest_schema import ManifestInspectSchema


router = APIRouter(
    prefix="/manifest",
    tags=["manifest"],
    dependencies=[Depends(verify_signature)],
)


@router.get(
    path="/inspect",
    description="Inspect image manifest",
    response_model=ManifestInspectSchema,
)
async def imagetools_inspect(
    spec_or_digest: str,
):
    return await asyncall(
        lambda: DOCKER.manifest.inspect(
            spec_or_digest, insecure=Config.DOCKER_INSECURE
        ),
        asyncall_timeout=60,
    )
