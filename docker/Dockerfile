# Arch Linux development and test environment for dapapa for Linux.
FROM archlinux:latest
RUN pacman -Syu --noconfirm --needed \
        base-devel git dotnet-sdk aspnet-runtime nftables libnetfilter_queue libmnl libnfnetlink \
        iproute2 tcpdump bind python sudo openssl ethtool procps-ng \
        fontconfig ttf-dejavu wayland libxkbcommon libx11 libice libsm libxrandr libxcursor libxi weston \
    && pacman -Scc --noconfirm
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 AVALONIA_TELEMETRY_OPTOUT=1 NUGET_PACKAGES=/nuget
WORKDIR /src
