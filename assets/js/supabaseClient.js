(function () {
  'use strict';

  if (!window.supabase || typeof window.supabase.createClient !== 'function') {
    console.error('[Cifrei] SDK do Supabase não carregado.');
    return;
  }

  const SUPABASE_URL = 'https://bgfchuxvuanjiepchfxq.supabase.co';
  const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_QJzlVnYT2CF8-BrTbsfOlw_EJcrY8bv';

  const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true
      }
    }
  );

  window.cifreiSupabase = client;
  window.supabaseClient = client;

  console.log('[Cifrei] Supabase client inicializado com sucesso.');
})();