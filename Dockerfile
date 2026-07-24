# OMO Signer — 生产部署 Docker 镜像
FROM python:3.12-slim

LABEL org.opencontainers.image.title="OMO Signer"
LABEL org.opencontainers.image.description="LLM 多智能体通信签名基础设施"
LABEL org.opencontainers.image.version="1.0.0"

WORKDIR /app

# 创建非root用户
RUN useradd -m -s /bin/bash omo

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 安装应用（非editable，生产镜像不依赖源码目录）
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

# 切换到非root用户
USER omo

# 持久化状态目录
VOLUME ["/home/omo/.local/state"]

# 暴露默认端口
EXPOSE 45987

# 默认启动守护进程
CMD ["omo-daemon"]
