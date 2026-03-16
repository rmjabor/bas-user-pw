(function () {
  'use strict';

  if (!window.supabase || typeof window.supabase.createClient !== 'function') {
    console.error('[BAS_UPW] SDK do Supabase não carregado.');
    return;
  }

  const SUPABASE_URL = 'https://pcbflajcmsbkunzhqoom.supabase.co';
  const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_ENnW7nvG_xYNwY1xxyPXPg_IEjTPw9z';

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

  console.log('[BAS_UPW] Supabase client inicializado com sucesso.');
})();