from setuptools import setup

setup(name="locoproto",
      author="kjy00302",
      version="0.1.0",
      packages=["locoproto"],
      description="Kakao LOCO protocol implementation",
      install_requires=["cryptography>=3.3", "bson>=0.5.10"]
)
