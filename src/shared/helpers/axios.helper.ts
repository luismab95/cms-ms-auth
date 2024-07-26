import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';

export async function sendRequestPost<T>(
  apiUrl: string,
  postData: T,
  headers: AxiosRequestConfig,
) {
  try {    
    const response: AxiosResponse = await axios.post(apiUrl, postData, headers);
    return response.data;
  } catch (error) {
    console.error((error as any).message);
  }
}
