// supabase/functions/admin-users/index.ts
// Edge Function: управление пользователями из админ-панели

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const ADMIN_EMAIL = 'esemenov85@gmail.com'

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

serve(async (req) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders })
    }

    try {
        // 1. Проверяем, что запрос от авторизованного пользователя
        const authHeader = req.headers.get('Authorization')
        if (!authHeader) {
            return json({ error: 'Нет токена авторизации' }, 401)
        }
        const jwt = authHeader.replace('Bearer ', '')

        // 2. Создаём клиент с anon key, но с JWT пользователя в заголовке.
        //    getUser() без аргумента проверит токен через Auth API Supabase.
        //    Это надёжнее, чем getUser(jwt) на клиенте с anon key.
        const supabaseAuth = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_ANON_KEY') ?? '',
            {
                global: {
                    headers: { Authorization: `Bearer ${jwt}` },
                },
            }
        )

        const { data: { user }, error: userError } = await supabaseAuth.auth.getUser()

        if (userError || !user) {
            console.error('Auth check failed:', userError?.message)
            return json({ error: 'Не удалось проверить пользователя: ' + (userError?.message || 'no user') }, 401)
        }

        // 3. Проверяем, что это админ
        if (user.email !== ADMIN_EMAIL) {
            return json({ error: 'Доступ запрещён: вы не администратор' }, 403)
        }

        // 4. Теперь можно использовать service_role
        const supabaseAdmin = createClient(
            Deno.env.get('SUPABASE_URL') ?? '',
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
        )

        // 5. Разбираем тело запроса
        const body = await req.json()
        const { action, payload } = body

        // 6. Обрабатываем действия
        switch (action) {
            case 'create_user': {
                const { email, password, first_name, last_name, phone, telegram, vk, max } = payload
                if (!email || !password || !first_name || !last_name) {
                    return json({ error: 'Обязательные поля: email, password, first_name, last_name' }, 400)
                }

                // Создаём пользователя в auth.users
                const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
                    email,
                    password,
                    email_confirm: true,   // сразу подтверждён
                    user_metadata: { first_name, last_name, phone, telegram, vk, max },
                })

                if (createError) {
                    console.error('createUser error:', createError)
                    return json({ error: createError.message }, 400)
                }

                return json({ success: true, user: created.user })
            }

            case 'reset_password': {
                const { user_id, new_password } = payload
                if (!user_id || !new_password) {
                    return json({ error: 'Нужны user_id и new_password' }, 400)
                }
                const { error } = await supabaseAdmin.auth.admin.updateUserById(user_id, {
                    password: new_password,
                })
                if (error) return json({ error: error.message }, 400)
                return json({ success: true })
            }

            case 'ban_user': {
                const { user_id, ban } = payload
                if (!user_id) {
                    return json({ error: 'Нужен user_id' }, 400)
                }

                // ban = true → блокируем на 100 лет, ban = false → снимаем блокировку
                const banDuration = ban ? '876000h' : 'none'  // 876000 часов ≈ 100 лет

                const { error } = await supabaseAdmin.auth.admin.updateUserById(user_id, {
                    ban_duration: banDuration,
                })

                if (error) {
                    console.error('ban error:', error)
                    return json({ error: error.message }, 400)
                }

                // Дублируем флаг в profiles для отображения в админке
                await supabaseAdmin
                    .from('profiles')
                    .update({ is_blocked: ban, updated_at: new Date().toISOString() })
                    .eq('id', user_id)

                return json({ success: true })
            }

            default:
                return json({ error: 'Неизвестное действие: ' + action }, 400)
        }
    } catch (e) {
        return json({ error: 'Внутренняя ошибка: ' + (e?.message ?? String(e)) }, 500)
    }
})

// Вспомогательная функция для JSON-ответа
function json(data: unknown, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })
}

