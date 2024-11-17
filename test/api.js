const axios = require('axios');

const API_BASE_URL = 'http://localhost:3000';

async function testFHEOperations() {
    try {
        // 1. 生成密钥
        const publicKey = "test_user_1";
        const keyGenResponse = await axios.post(`${API_BASE_URL}/generate_keys`, {
            public_key: publicKey
        });
        // console.log('Generated Keys:', keyGenResponse.data);
        console.log('Generated Keys Generated');

        // 2. 获取FHE公钥
        const pubKeyResponse = await axios.get(`${API_BASE_URL}/get_public_key`, {
            data: { public_key: publicKey }
        });
        // console.log('Retrieved Public Key:', pubKeyResponse.data);
        console.log('Retrieved Public Key');

        // 3. 加密一些数据
        const encryptedValues = [];
        const valuesToEncrypt = [1, 2, 3, 4, 5];
        
        for (const value of valuesToEncrypt) {
            const encryptResponse = await axios.post(`${API_BASE_URL}/encrypt`, {
                public_key: publicKey,
                data_type: "int8",
                value: value
            });
            encryptedValues.push(encryptResponse.data.encrypted_value);
            // console.log(`Encrypted ${value}:`, encryptResponse.data);
            console.log(`Encrypted ${value}`);
        }

        // 4. 计算加密数据的和
        const computeResponse = await axios.post(`${API_BASE_URL}/compute`, {
            task_id: "sum_task_1",
            data_type: "int8",
            encrypted_values: encryptedValues
        });
        // console.log('Computation Result:', computeResponse.data);
        console.log('Computation Result');

    } catch (error) {
        console.error('Error during FHE operations:', error);
        if (axios.isAxiosError(error)) {
            console.error('Response data:', error.response?.data);
        }
    }
}

// 运行测试
testFHEOperations(); 