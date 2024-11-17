# ... existing code ...

# 修改 CUDA 架构设置
set(CMAKE_CUDA_ARCHITECTURES 86)  # 使用 8.6 而不是 8.9
# 或者尝试多个架构
# set(CMAKE_CUDA_ARCHITECTURES 75 80 86)

# ... rest of the code ... 