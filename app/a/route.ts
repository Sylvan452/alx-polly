import { NextResponse } from 'next/server'
import { getPollById } from '@/app/lib/actions/poll-actions'
import { createClient } from '@/lib/supabase/server'

export async function POST(req: Request, { params }: { params: { id: string }}) {
  const { id } = params
  const body = await req.json().catch(() => ({}))
  const { optionId } = body

  if (!optionId) {
    return NextResponse.json({ error: 'optionId required' }, { status: 400 })
  }

  // check poll exists (mock or real DB)
  const { poll, error: pollError } = await getPollById(id)
  if (pollError || !poll) {
    return NextResponse.json({ error: pollError || 'Poll not found' }, { status: 404 })
  }

  // create a server Supabase client
  const supabase = await createClient()

  // insert a vote row. adjust table and column names to your schema
  const { error } = await supabase
    .from('votes')
    .insert({ poll_id: id, option_id: optionId })

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 })
  }

  return NextResponse.json({ ok: true }, { status: 200 })
}
