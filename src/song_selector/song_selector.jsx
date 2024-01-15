import { useState, useEffect } from 'react'
import './song_selector.css'

function SongSelector({ onSongSelect }) {
  const [selectedSong, setSelectedSong] = useState('')
  const [songs, setSongs] = useState(["Song1", "Song2", "Song3"])

  /*
  useEffect(() => {
    // Fetch songs from the API
    fetch('https://example.com/api/songs')
      .then(response => response.json())
      .then(data => setSongs(data))
      .catch(error => console.error(error))
  }, [])
  */

  const handleSongChange = (event) => {
    const song = event.target.value
    setSelectedSong(song)
    onSongSelect(song) // Call the callback function with the selected song
  }

  return (
    <>
      <select className="song-selector" value={selectedSong} onChange={handleSongChange}>
        <option value="">Song auswählen</option>
        {songs.map((song, index) => (
          <option key={index} value={song}>
            {song}
          </option>
        ))}
      </select>
    </>
  )
}

export default SongSelector