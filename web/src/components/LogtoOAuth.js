import React, { useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {API, showError, showSuccess, updateAPI} from '../helpers';
import { UserContext } from '../context/User';
import {setUserData} from "../helpers/data.js";

const LogtoRedirectHandler = () => {
    const [userState, userDispatch] = useContext(UserContext);
    let navigate = useNavigate();

    useEffect(() => {
        const checkLoginStatus = async () => {
            try {
                const res = await API.get('/api/logto_status');
                const { success, data } = res.data;

                if (success) {
                    // 如果已登录，更新用户状态并跳转到主页
                    userDispatch({ type: 'login', payload: data });
                    localStorage.setItem('user', JSON.stringify(data));
                    setUserData(data);
                    updateAPI()
                    showSuccess('登录成功！');
                    navigate('/'); // 跳转到主页
                } else {
                    showError('用户未登录，请重新登录。');
                    navigate('/login'); // 跳转到登录页面
                }
            } catch (error) {
                console.error('获取登录状态失败:', error);
                showError('登录失败，请重试！');
                navigate('/login'); // 跳转到登录页面
            }
        };

        checkLoginStatus();
    }, [navigate, userDispatch]);

    return null; // 简化组件，不显示内容
};

export default LogtoRedirectHandler;
