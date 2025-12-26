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
		if (req.query.metric == 'l7Flow_flux'){
			var action = 'DescribeSiteTimeSeriesData';
			var name = 'Traffic';
			var metric = 'ALL';
		}
		if (req.query.metric == 'l7Flow_inFlux'){
			var action = 'DescribeSiteTimeSeriesData';
			var name = 'RequestTraffic';
			var metric = 'ALL';
		}
		if (req.query.metric == 'l7Flow_outFlux'){
			var action = 'DescribeSiteTimeSeriesData';
			var name = 'Traffic';
			var metric = 'ALL';
		}
		if (req.query.metric == 'l7Flow_request'){
			var action = 'DescribeSiteTimeSeriesData';
			var name = 'Requests';
			var metric = 'ALL';
		}
		if (req.query.metric == 'l7Flow_request_country'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientCountryCode';
		}
		if (req.query.metric == 'l7Flow_outFlux_country'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientCountryCode';
		}
		if (req.query.metric == 'l7Flow_outFlux_province'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientProvinceCode';
		}
		if (req.query.metric == 'l7Flow_request_province'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientProvinceCode';
		}
		if (req.query.metric == 'l7Flow_outFlux_statusCode'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'EdgeResponseStatusCode';
		}
		if (req.query.metric == 'l7Flow_request_statusCode'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'EdgeResponseStatusCode';
		}
		if (req.query.metric == 'l7Flow_outFlux_domain'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientRequestHost';
		}
		if (req.query.metric == 'l7Flow_request_domain'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientRequestHost';
		}
		if (req.query.metric == 'l7Flow_outFlux_url'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientRequestPath';
		}
		if (req.query.metric == 'l7Flow_request_url'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientRequestPath';
		}
		if (req.query.metric == 'l7Flow_outFlux_resourceType'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'EdgeResponseContentType';
		}
		if (req.query.metric == 'l7Flow_request_resourceType'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'EdgeResponseContentType';
		}
		if (req.query.metric == 'l7Flow_outFlux_sip'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientIP';
		}
		if (req.query.metric == 'l7Flow_request_sip'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientIP';
		}
		if (req.query.metric == 'l7Flow_outFlux_referers'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientRequestReferer';
		}
		if (req.query.metric == 'l7Flow_request_referers'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientRequestReferer';
		}
		if (req.query.metric == 'l7Flow_outFlux_ua_os'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientOS';
		}
		if (req.query.metric == 'l7Flow_request_ua_os'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientOS';
		}
		if (req.query.metric == 'l7Flow_outFlux_ua'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientRequestUserAgent';
		}
		if (req.query.metric == 'l7Flow_request_ua'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientRequestUserAgent';
		}
		if (req.query.metric == 'l7Flow_outFlux_ua_device'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'ClientRequestMethod';
		}
		if (req.query.metric == 'l7Flow_request_ua_device'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'ClientRequestMethod';
		}
		if (req.query.metric == 'l7Flow_outFlux_ua_browser'){
			var action = 'DescribeSiteTopData';
			var name = 'Traffic';
			var metric = 'EdgeCacheStatus';
		}
		if (req.query.metric == 'l7Flow_request_ua_browser'){
			var action = 'DescribeSiteTopData';
			var name = 'Requests';
			var metric = 'EdgeCacheStatus';
		}
		const Limit = req.query.Limit || "5";
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
            SiteId: siteIdFromQuery || '1036556791122480', // 从查询参数获取或为空字符串
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
        const httpMethod = 'GET'; 

        const aliyunSigningPath = '/'; 
        const stringToSign = `${httpMethod}&${percentEncode(aliyunSigningPath)}&${percentEncode(canonicalizedQueryString)}`;

        const signature = await calculateHmacSha1Base64(secretKey, stringToSign);

        coreParams.Signature = signature;
		
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
		
    if (
  // 修复逻辑运算符优先级：给||条件加括号
  (req.query.metric === 'l7Flow_flux' || req.query.metric === 'l7Flow_inFlux' || req.query.metric === 'l7Flow_outFlux' || req.query.metric === 'l7Flow_request') 
  && apiData.Data 
  && apiData.Data.length > 0
) {
  // 1. 安全获取SummarizedData中的Value值（容错处理）
  const trafficValue = apiData.SummarizedData?.[0]?.Value || 0;

  // 2. 处理DetailData：转换TimeStamp为秒级时间戳 + 修正字段名
  const detailList = (apiData.Data[0].DetailData || []).map(item => ({
    Value: item.Value || 0,
    // 核心：ISO时间字符串 → 秒级时间戳（取整避免小数）
    Timestamp: item.TimeStamp 
      ? Math.floor(new Date(item.TimeStamp).getTime() / 1000) 
      : 0 
  }));

  // 3. 构建最终的TypeValue结构（包含Detail子数组）
  apiData.Data[0].TypeValue = [
    {
      MetricName: req.query.metric,
      Sum: trafficValue,
      Detail: detailList // 替换为转换后的Detail列表
    }
  ];
	delete apiData.Data[0].DetailData;
 
  delete apiData.SummarizedData;
}

if (
  req.query.metric === 'l7Flow_request_country' || req.query.metric === 'l7Flow_outFlux_country' || req.query.metric === 'l7Flow_outFlux_province' ||req.query.metric === 'l7Flow_request_province' || req.query.metric === 'l7Flow_outFlux_statusCode' || req.query.metric === 'l7Flow_request_statusCode' ||req.query.metric === 'l7Flow_outFlux_domain' || req.query.metric === 'l7Flow_request_domain'||req.query.metric === 'l7Flow_outFlux_url' || req.query.metric === 'l7Flow_request_url'||req.query.metric === 'l7Flow_outFlux_resourceType' || req.query.metric === 'l7Flow_request_resourceType'||req.query.metric === 'l7Flow_outFlux_sip' || req.query.metric === 'l7Flow_request_sip'||req.query.metric === 'l7Flow_outFlux_referers' || req.query.metric === 'l7Flow_request_referers'||req.query.metric === 'l7Flow_outFlux_ua_os' || req.query.metric === 'l7Flow_request_ua_os'||req.query.metric === 'l7Flow_outFlux_ua' || req.query.metric === 'l7Flow_request_ua'||req.query.metric === 'l7Flow_outFlux_ua_device' || req.query.metric === 'l7Flow_request_ua_device'||req.query.metric === 'l7Flow_outFlux_ua_browser' || req.query.metric === 'l7Flow_request_ua_browser'
  && apiData.Data 
  && apiData.Data.length > 0
) {
  // 遍历Data数组，处理每个元素的DetailData
  apiData.Data.forEach(dataItem => {
    // 检查DetailData是否存在且为数组
    if (dataItem.DetailData && Array.isArray(dataItem.DetailData)) {
      // 遍历DetailData，替换DimensionValue为Key
      dataItem.DetailData = dataItem.DetailData.map(detailItem => {
        // 构建新对象：保留所有字段，替换DimensionValue为Key
        const newDetailItem = { ...detailItem };
        // 如果存在DimensionValue字段
        if (newDetailItem.DimensionValue !== undefined) {
          // 新增Key字段，赋值为原DimensionValue的值
          newDetailItem.Key = newDetailItem.DimensionValue;
          // 删除原DimensionValue字段
          delete newDetailItem.DimensionValue;
        }
        return newDetailItem;
      });
    }
  });
}
        return res.json(apiData);
        
    } catch (error) {
        console.error('Error in EdgeOne Pages Function /traffic:', error.message, error.stack);
        return res.status(500).json({ 
            error: `Server internal error: ${error.message}`
        });
    }
});

export default app;