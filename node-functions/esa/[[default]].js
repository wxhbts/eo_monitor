import express from 'express';
import path from 'path';
import fs from 'fs';
import 'dotenv/config';


const app = express();

// Function to read keys
function getKeys() {
    // 1. Try Environment Variables first
    let secretId = process.env.ESASECRET_ID;
    let secretKey = process.env.ESASECRET_KEY;

    if (secretId && secretKey) {
        return { secretId, secretKey };
    }

    // 2. Try key.txt if Env Vars are missing
    try {
        // const keyPath = path.resolve(__dirname, '../../key.txt');
        const keyPath = path.resolve(process.cwd(), 'key.txt');
        
        if (fs.existsSync(keyPath)) {
            const content = fs.readFileSync(keyPath, 'utf-8');
            const lines = content.split('\n');
            
            lines.forEach(line => {
                if (line.includes('accessKeyId') && !secretId) {
                    secretId = line.split('：')[1].trim();
                }
                if (line.includes('accessKeySecret') && !secretKey) {
                    secretKey = line.split('：')[1].trim();
                }
            });
        }
    } catch (err) {
        console.error("Error reading key.txt:", err);
    }

    return { secretId, secretKey };
}

app.get('/config', (req, res) => {
    res.json({
        siteName: process.env.SITE_NAME || 'AcoFork 的 EdgeOne 监控大屏',
        siteIcon: process.env.SITE_ICON || 'https://q2.qlogo.cn/headimg_dl?dst_uin=2726730791&spec=0'
    });
});

function percentEncode(str) {
    if (str === null || str === undefined) {
        return '';
    }
    let encodedStr = encodeURIComponent(str);
    encodedStr = encodedStr.replace(/\+/g, '%20');
    encodedStr = encodedStr.replace(/\*/g, '%2A');
    encodedStr = encodedStr.replace(/%7E/g, '~');
    return encodedStr;
}
// HMAC-SHA1 签名计算函数 (保持不变)
async function calculateHmacSha1Base64(secretKey, stringToSign) {
    const finalSecretKey = secretKey + '&';
    const encoder = new TextEncoder();
    try {
        const keyBytes = encoder.encode(finalSecretKey);
        const messageBytes = encoder.encode(stringToSign);
        // Web Crypto API 在 EdgeOne Functions 环境下应该是可用的
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        );
        const signatureBuffer = await crypto.subtle.sign(
            'HMAC',
            cryptoKey,
            messageBytes
        );
        function arrayBufferToBase64(buffer) {
            let binary = '';
            const bytes = new Uint8Array(buffer);
            const len = bytes.byteLength;
            for (let i = 0; i < len; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            return btoa(binary);
        }
        return arrayBufferToBase64(signatureBuffer);
    } catch (error) {
        console.error('Error during HMAC-SHA1 calculation:', error);
        throw new Error(`HMAC-SHA1 calculation failed: ${error.message}`);
    }
}

app.get('/traffic', async (req, res) => {
    try {

        const { secretId, secretKey } = getKeys(); // 你的密钥获取函数
        
        if (!secretId || !secretKey) {
            return res.status(500).json({ error: "Missing credentials" });
        }
		
        const now = new Date();
        const formatDate = (date) => {
             // 格式化为 ISO 8601 字符串，例如 2025-12-24T22:07:26Z
             return date.toISOString().slice(0, 19) + 'Z';
        };

        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000); // 24小时前
        const metric = req.query.dimension || "ALL";
		const name = req.query.name || "Traffic";
		const Limit = req.query.Limit || "5";
		const action = req.query.action || "DescribeSiteTopData";
        const startTime = req.query.startTime || formatDate(yesterday);
        const endTime = req.query.endTime || formatDate(now);
        const interval = req.query.interval || "60";
        const siteIdFromQuery = req.query.siteId; // 从查询参数获取
        const signatureNonce = Math.random().toString(36).substring(2) + Date.now();
        const timestamp = formatDate(now);

        // 1. 构建原始参数对象 (注意 Fields 需要 JSON.stringify)
        let coreParams = {
            AccessKeyId: secretId,
            Action: action,
            EndTime: endTime,
            Fields: JSON.stringify([{ FieldName: name, Dimension: [metric] }]), // Fields 必须是 JSON 字符串
            Format: 'json',
            Interval: interval,
			Limit: Limit,
            Metric: metric,
            SignatureMethod: 'HMAC-SHA1',
            SignatureNonce: signatureNonce, // 动态生成
            SignatureVersion: '1.0',
            SiteId: siteIdFromQuery || '', // 从查询参数获取或为空字符串
            StartTime: startTime,
            Timestamp: timestamp, // 动态生成且格式化
            Version: '2024-09-10'
        };

        Object.keys(coreParams).forEach(key => {
            if (coreParams[key] === null || coreParams[key] === undefined) {
                delete coreParams[key];
            }
        });
        const sortedKeys = Object.keys(coreParams).sort();
        let canonicalizedQueryString = '';
        sortedKeys.forEach(key => {
            const value = coreParams[key];
            canonicalizedQueryString += `&${percentEncode(key)}=${percentEncode(value)}`;
        });
        canonicalizedQueryString = canonicalizedQueryString.substring(1);
        const httpMethod = 'GET'; // Your Express route is app.get
        // For Aliyun signing, the path is often just `/`
        const aliyunSigningPath = '/'; 
        const stringToSign = `${httpMethod}&${percentEncode(aliyunSigningPath)}&${percentEncode(canonicalizedQueryString)}`;
        //console.log('StringToSign:', stringToSign);
        const signature = await calculateHmacSha1Base64(secretKey, stringToSign);
        
        //console.log('Signature:', signature);
        coreParams.Signature = signature;
        //console.log('Final Request Params:', coreParams);
		
        const finalQueryParams = new URLSearchParams(coreParams).toString();

        const aliyunApiEndpoint = 'https://esa.cn-hangzhou.aliyuncs.com';
		
        const apiUrl = `${aliyunApiEndpoint}/?${finalQueryParams}`; 
        
        //console.log('Fetching from Aliyun API URL:', apiUrl);
        const apiResponse = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        });
        if (!apiResponse.ok) {
            const errorText = await apiResponse.text();
            console.error('Aliyun API Error Response:', errorText);
            return res.status(apiResponse.status).json({ 
                error: `Failed to fetch data from Aliyun API: ${apiResponse.status} ${apiResponse.statusText}`,
                aliyunError: errorText
            });
        }
        const apiData = await apiResponse.json();
        return res.json(apiData);
        
    } catch (error) {
        console.error('Error in EdgeOne Pages Function /traffic:', error.message, error.stack);
        return res.status(500).json({ 
            error: `Server internal error: ${error.message}`
        });
    }
});

export default app;
