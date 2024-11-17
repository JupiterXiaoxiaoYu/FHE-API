import axios from 'axios';

const API_BASE_URL = 'http://localhost:3000';
const BATCH_SIZE = 5; // 每批处理的数据量

// 创建axios实例，设置更长的超时时间
const api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 30000, // 30秒
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
});

async function testFHEOperations() {
    try {
        // 1. 生成密钥
        const publicKey = "test_user_1";
        const keyGenResponse = await api.post('/generate_keys', {
            public_key: publicKey
        });
        console.log('Generated Keys:', keyGenResponse.data);

        // 2. 获取FHE公钥
        const pubKeyResponse = await api.get('/get_public_key', {
            data: { public_key: publicKey }
        });
        console.log('Retrieved Public Key:', pubKeyResponse.data);

        // 3. 加密数据
        const valuesToEncrypt = [1, 2, 3, 4, 5];
        const encryptedValues = await Promise.all(
            valuesToEncrypt.map(value => 
                api.post('/encrypt', {
                    public_key: publicKey,
                    data_type: "int8",
                    value: value
                })
            )
        );
        
        const encryptedResults = encryptedValues.map(response => response.data.encrypted_value);
        console.log(`Encrypted ${valuesToEncrypt.length} values`);

        // 4. 分批计算
        const batches = [];
        for (let i = 0; i < encryptedResults.length; i += BATCH_SIZE) {
            batches.push(encryptedResults.slice(i, i + BATCH_SIZE));
        }

        let finalResult;
        for (let i = 0; i < batches.length; i++) {
            const computeResponse = await api.post('/compute', {
                task_id: `sum_task_batch_${i}`,
                data_type: "int8",
                encrypted_values: batches[i]
            }, {
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (i === 0) {
                finalResult = computeResponse.data.result;
            } else {
                // 如果有多个批次，需要再次调用compute合并结果
                const mergeResponse = await api.post('/compute', {
                    task_id: `sum_task_merge_${i}`,
                    data_type: "int8",
                    encrypted_values: [finalResult, computeResponse.data.result]
                });
                finalResult = mergeResponse.data.result;
            }
        }

        console.log('Final Computation Result:', finalResult);

    } catch (error) {
        console.error('Error during FHE operations:', error);
        if (axios.isAxiosError(error)) {
            console.error('Response data:', error.response?.data);
            console.error('Error status:', error.response?.status);
            console.error('Error message:', error.message);
        }
    }
}

// 运行测试
testFHEOperations().catch(console.error); 