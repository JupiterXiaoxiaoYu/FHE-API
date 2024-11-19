const axios = require('axios');
const http = require('http');

const API_BASE_URL = 'http://localhost:3000';
const DELAY_MS = 10000;

// 创建 axios 实例，配置更长的超时时间和更大的数据限制
const api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 120000,  // 2分钟超时
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    headers: {
        'Content-Type': 'application/json',
    },
    // 禁用 keep-alive
    httpAgent: new http.Agent({ 
        keepAlive: false,
        timeout: 120000
    })
});


async function testFHEOperations() {
    try {
        // 1. 生成密钥
        const publicKey = "test_user_1";
        const serverKey = "";
        const keyGenResponse = await axios.post(`${API_BASE_URL}/generate_keys`, {
            public_key: publicKey,
            server_key: serverKey
        });
        console.log('Generated Keys:', keyGenResponse.data);
        console.log('Generated Keys Generated');


        // 2. 获取FHE公钥
        const pubKeyResponse = await axios.get(`${API_BASE_URL}/get_public_key`, {
            data: { public_key: publicKey }
        });
        // console.log('Retrieved Public Key:', pubKeyResponse.data);
        console.log('Retrieved Public Key');

        // 3. 加密一些数据
        const encryptedValues = [];
        const valuesToEncrypt = [1, 2, 3, 4, 5, 6, 7];
        
        for (const value of valuesToEncrypt) {
            const encryptResponse = await axios.post(`${API_BASE_URL}/encrypt`, {
                public_key: publicKey,
                data_type: "int8",
                value: value
            });
            encryptedValues.push(encryptResponse.data.encrypted_value);
            // console.log(`Encrypted ${value}:`, encryptResponse.data);
            console.log(`Encrypted ${value}, type of encrypted_value: ${typeof encryptResponse.data.encrypted_value}`);
        }

        // 4. 计算加密数据的和
        const finalResult = await axios.post(`${API_BASE_URL}/compute`, {
            public_key: publicKey,
            task_id: 'sum_task',
            data_type: "int8",
            encrypted_values: encryptedValues
        });
        if (!finalResult) {
            throw new Error('No result obtained from computation');
        }
        console.log('Final computation completed');

        // 5. 解密结果
        const decryptResponse = await axios.post(`${API_BASE_URL}/decrypt`, {
            public_key: publicKey,
            data_type: "int8",
            encrypted_value: finalResult.data.result
        });
        console.log('Decrypted Result:', decryptResponse.data.value);
    
    } catch (error) {
        console.error('Error during FHE operations:', error);
        if (axios.isAxiosError(error)) {
            if (error.response) {
                console.error('Response status:', error.response.status);
                // console.error('Response data:', error.response.data);
            }
            // console.error('Request data:', error.config?.data);
        }
    }
}

// 运行测试
testFHEOperations(); 